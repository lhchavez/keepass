extern crate clap;
extern crate crypto;
extern crate cursive;
extern crate cursive_tree_view;
extern crate flate2;
extern crate rpassword;
extern crate sxd_document;

use clap::{App, Arg};
use cursive::traits::*;
use cursive::view::Margins;
use cursive::views::{
    Button, Dialog, EditView, LinearLayout, ListView, OnEventView, Panel, SelectView, TextArea,
    TextView, ViewRef,
};
use cursive::{Cursive, CursiveExt};
use cursive_tree_view::{Placement, TreeView};
use keys::Key;

mod database;
mod keys;
mod streams;

#[derive(Debug)]
struct TreeEntry {
    name: String,
    is_group: bool,
    uuid: String,
}

impl std::fmt::Display for TreeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone)]
struct DatabaseRef {
    db: std::rc::Weak<database::Database>,
    selected_uuid: std::rc::Rc<std::cell::RefCell<String>>,
}

impl DatabaseRef {
    pub fn new(
        db: &std::rc::Rc<database::Database>,
        selected_uuid: &std::rc::Rc<std::cell::RefCell<String>>,
    ) -> DatabaseRef {
        DatabaseRef {
            db: std::rc::Rc::downgrade(db),
            selected_uuid: selected_uuid.clone(),
        }
    }

    pub fn search(&self, siv: &mut Cursive, text: &str) {
        siv.pop_layer();

        let mut select: ViewRef<SelectView<TreeEntry>> = siv.find_name("select").unwrap();
        if let Err(e) = siv.focus_name("select") {
            println!("{:?}", e);
        }
        select.clear();

        let db_option = self.db.upgrade();
        if db_option.is_none() {
            return;
        }
        let db = db_option.unwrap();

        select.add_all(db.search(text).iter().map(|entry| {
            (
                entry.title.clone(),
                TreeEntry {
                    name: entry.title.clone(),
                    is_group: false,
                    uuid: entry.uuid.clone(),
                },
            )
        }));
    }

    pub fn display_entry(&self, siv: &mut Cursive, uuid: &str) {
        let db_option = self.db.upgrade();
        if db_option.is_none() {
            return;
        }
        let db = db_option.unwrap();
        let entry_option = db.find_entry_by_uuid(uuid);
        if entry_option.is_none() {
            return;
        }
        *self.selected_uuid.borrow_mut() = uuid.to_string();
        let entry = entry_option.unwrap();
        siv.call_on_name("title", |edit: &mut EditView| {
            edit.set_content(entry.title.clone());
        });
        siv.call_on_name("username", |edit: &mut EditView| {
            edit.set_content(entry.user_name.clone());
        });
        siv.call_on_name("url", |edit: &mut EditView| {
            edit.set_content(entry.url.clone());
        });
        siv.call_on_name("password", |edit: &mut EditView| {
            edit.set_secret(true);
            edit.set_content("password");
        });
        siv.call_on_name("notes", |edit: &mut TextArea| {
            edit.set_content(entry.notes.clone());
        });
    }

    pub fn reveal_password(&self, siv: &mut Cursive) {
        let db_option = self.db.upgrade();
        if db_option.is_none() {
            return;
        }
        let db = db_option.unwrap();
        let entry_option = db.find_entry_by_uuid(&self.selected_uuid.borrow());
        if entry_option.is_none() {
            return;
        }
        let entry = entry_option.unwrap();
        siv.call_on_name("password", |edit: &mut EditView| {
            edit.set_secret(false);
            edit.set_content(String::from(&entry.password));
        });
    }
}

fn main() {
    let matches = App::new("KeePass")
        .version("1.0.0")
        .author("lhchavez <lhchavez@lhchavez.com>")
        .about("A commandline implementation of KeePass")
        .arg(
            Arg::with_name("DATABASE")
                .help(".kdbx database")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("password-file")
                .help("File where the composite password is stored")
                .long("password-file")
                .value_name("FILE")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("save-password")
                .help("Save the composite password into a file")
                .long("save-password")
                .value_name("FILE")
                .takes_value(true),
        )
        .get_matches();

    let key = match matches.value_of("password-file") {
        Some(password_file) => keys::CompositeKey::new_from_file(password_file).unwrap(),
        None => {
            let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
            keys::CompositeKey::new(&[keys::PasswordKey::new(password.as_str()).key()])
        }
    };
    if let Some(save_file) = matches.value_of("save-password") {
        key.save_to_file(save_file).unwrap();
        return;
    }

    fn populate_groups(
        tree_view: &mut TreeView<TreeEntry>,
        group: &database::Group,
        parent_group_pos: usize,
    ) {
        let group_pos = tree_view
            .insert_container_item(
                TreeEntry {
                    name: group.name.clone(),
                    is_group: true,
                    uuid: group.uuid.clone(),
                },
                Placement::LastChild,
                parent_group_pos,
            )
            .unwrap();
        // Container items are always inserted collapsed, so we need to uncollapse them before
        // adding children.
        tree_view.expand_item(group_pos);
        for child_group in &group.groups {
            populate_groups(tree_view, child_group, group_pos);
        }

        for entry in &group.entries {
            tree_view.insert_item(
                TreeEntry {
                    name: entry.title.clone(),
                    is_group: false,
                    uuid: entry.uuid.clone(),
                },
                Placement::LastChild,
                group_pos,
            );
        }
    }

    let db_path = matches.value_of("DATABASE").unwrap();
    let db = std::rc::Rc::new(database::Database::open(db_path, &key).unwrap());
    let selected_uuid = std::rc::Rc::new(std::cell::RefCell::new(String::new()));

    let mut tree_view = TreeView::<TreeEntry>::new();
    for group in &db.groups {
        populate_groups(&mut tree_view, group, 0);
    }
    let db_ref_for_submit = DatabaseRef::new(&db, &selected_uuid);
    tree_view.set_on_submit(move |siv: &mut Cursive, row: usize| {
        let tree: ViewRef<TreeView<TreeEntry>> = siv.find_name("tree").unwrap();
        let selected_option = tree.borrow_item(row);
        if selected_option.map_or(true, |e| e.is_group) {
            return;
        }
        let option = selected_option.unwrap();
        db_ref_for_submit.display_entry(siv, &option.uuid)
    });

    let mut siv = Cursive::default();

    let db_ref_for_search = DatabaseRef::new(&db, &selected_uuid);
    siv.add_global_callback('/', move |siv| {
        if siv.screen().len() > 1 {
            return;
        }
        let db_ref_for_submit = db_ref_for_search.clone();
        let db_ref_for_search = db_ref_for_search.clone();
        siv.add_layer(
            OnEventView::new(
                Dialog::new()
                    .title("Search")
                    .content(
                        LinearLayout::vertical()
                            .child(TextView::new("Search:"))
                            .child(
                                EditView::new()
                                    .on_submit(move |siv: &mut Cursive, text: &str| {
                                        db_ref_for_submit.search(siv, text)
                                    })
                                    .with_name("search"),
                            ),
                    )
                    .padding(Margins::lrtb(10, 10, 2, 2))
                    .dismiss_button("Cancel")
                    .button("Search", move |s| {
                        let text = s
                            .call_on_name("search", |view: &mut EditView| view.get_content())
                            .unwrap();
                        db_ref_for_search.search(s, &text);
                    }),
            )
            .on_event(cursive::event::Event::Key(cursive::event::Key::Esc), |s| {
                s.pop_layer();
            }),
        );
    });
    siv.add_global_callback('q', |siv| {
        if siv.screen().len() > 1 {
            return;
        }
        siv.add_layer(
            OnEventView::new(
                Dialog::around(TextView::new("Quit KeePass?"))
                    .title("KeePass")
                    .padding(Margins::lrtb(10, 10, 2, 2))
                    .dismiss_button("Cancel")
                    .button("Quit", |s| s.quit()),
            )
            .on_event(cursive::event::Event::Key(cursive::event::Key::Esc), |s| {
                s.pop_layer();
            }),
        );
    });

    let db_ref_for_select = DatabaseRef::new(&db, &selected_uuid);
    let db_ref_for_reveal = DatabaseRef::new(&db, &selected_uuid);
    siv.add_fullscreen_layer(
        Dialog::around(
            LinearLayout::horizontal()
                .child(
                    LinearLayout::vertical()
                        .child(
                            Panel::new(tree_view.with_name("tree").scrollable())
                                .title("Groups")
                                .full_height(),
                        )
                        .child(
                            Panel::new(
                                SelectView::<TreeEntry>::new()
                                    .on_submit(move |siv, entry| {
                                        db_ref_for_select.display_entry(siv, &entry.uuid);
                                    })
                                    .with_name("select")
                                    .scrollable(),
                            )
                            .title("Search")
                            .full_height(),
                        ),
                )
                .child(Panel::new(
                    ListView::new()
                        .child("Title", EditView::new().disabled().with_name("title"))
                        .child("Username", EditView::new().disabled().with_name("username"))
                        .child("URL", EditView::new().disabled().with_name("url"))
                        .child(
                            "Password",
                            LinearLayout::horizontal()
                                .child(
                                    EditView::new()
                                        .disabled()
                                        .secret()
                                        .with_name("password")
                                        .full_width(),
                                )
                                .child(
                                    Button::new("Show", move |siv| {
                                        db_ref_for_reveal.reveal_password(siv)
                                    })
                                    .with_name("show"),
                                )
                                .full_width(),
                        )
                        .child(
                            "Notes",
                            TextArea::new().disabled().with_name("notes").full_height(),
                        )
                        .full_width()
                        .full_height()
                        .scrollable(),
                ))
                .full_width()
                .full_height(),
        )
        .title(db_path),
    );

    siv.run();
}
