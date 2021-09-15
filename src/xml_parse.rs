use crate::crypt::ciphers::Cipher;
use crate::result::{DatabaseIntegrityError, Error, Result};
use byteorder::{LittleEndian, WriteBytesExt};

use secstr::SecStr;

use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};
use xml::writer::{EmitterConfig, EventWriter, Result as WResult, XmlEvent as WXmlEvent};

use std::io::Write;

use super::db::{
    AutoType, AutoTypeAssociation, Database, Entry, Group, Meta, Node as DBNode, Value,
};

#[derive(Debug)]
enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, Value),
    AutoType(AutoType),
    AutoTypeAssociation(AutoTypeAssociation),
    ExpiryTime(String),
    Expires(bool),
    Meta(Meta),
    UUID(String),
    RecycleBinUUID(String),
}

pub(crate) trait Serializable {
    fn serialize<W: Write>(
        &self,
        w: &mut EventWriter<W>,
        encryptor: &mut dyn Cipher,
    ) -> WResult<()>;
}

fn write_simple_element<W: Write>(w: &mut EventWriter<W>, tag: &str, value: &str) -> WResult<()> {
    w.write(WXmlEvent::start_element(tag))?;
    w.write(WXmlEvent::characters(value))?;
    w.write(WXmlEvent::end_element())?;
    Ok(())
}

impl Serializable for Meta {
    fn serialize<W: Write>(
        &self,
        w: &mut EventWriter<W>,
        _encryptor: &mut dyn Cipher,
    ) -> WResult<()> {
        w.write(WXmlEvent::start_element("Meta"))?;

        w.write(WXmlEvent::start_element("RecycleBinUUID"))?;
        w.write(WXmlEvent::characters(&self.recyclebin_uuid))?;
        w.write(WXmlEvent::end_element())?;
        // some HashMap containing all unknown keys?

        w.write(WXmlEvent::end_element())?;
        Ok(())
    }
}

impl Serializable for Entry {
    fn serialize<W: Write>(
        &self,
        w: &mut EventWriter<W>,
        encryptor: &mut dyn Cipher,
    ) -> WResult<()> {
        w.write(WXmlEvent::start_element("Entry"))?;

        w.write(WXmlEvent::start_element("UUID"))?;
        w.write(WXmlEvent::characters(&self.uuid))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("IconID"))?;
        w.write(WXmlEvent::characters(&self.icon_id.to_string()))?;
        w.write(WXmlEvent::end_element())?;

        write_simple_element(w, "Expires", if self.expires { "True" } else { "False" })?;
        // ForegroundColor, BackgroundColor, OverrideURL, Tags

        for field_name in self.fields.keys() {
            w.write(WXmlEvent::start_element("String"))?;
            w.write(WXmlEvent::start_element("Key"))?;
            w.write(WXmlEvent::characters(&field_name))?;
            w.write(WXmlEvent::end_element())?;
            match self.fields.get(field_name) {
                Some(&Value::Bytes(_)) => {
                    w.write(WXmlEvent::start_element("Value"))?;
                    // FIXME: no bytes value
                    w.write(WXmlEvent::end_element())?;
                }
                Some(&Value::Protected(ref pv)) => {
                    w.write(WXmlEvent::start_element("Value").attr("Protected", "True"))?;

                    let plain = std::str::from_utf8(pv.unsecure())
                        .ok()
                        .unwrap()
                        .as_bytes()
                        .to_vec();

                    if plain.len() > 0 {
                        let buf_encrypted = encryptor.encrypt(&plain).unwrap();
                        let buf_encoded = base64::encode(&buf_encrypted);

                        w.write(WXmlEvent::characters(&buf_encoded))?;
                    }
                    w.write(WXmlEvent::end_element())?;
                }
                Some(&Value::Unprotected(ref uv)) => {
                    w.write(WXmlEvent::start_element("Value"))?;
                    w.write(WXmlEvent::characters(&uv))?;
                    w.write(WXmlEvent::end_element())?;
                }
                None => {
                    w.write(WXmlEvent::start_element("Value"))?;
                    w.write(WXmlEvent::end_element())?;
                }
            };

            w.write(WXmlEvent::end_element())?;
        }

        if let Some(at) = &self.autotype {
            w.write(WXmlEvent::start_element("AutoType"))?;
            write_simple_element(w, "Enabled", if at.enabled { "True" } else { "False" })?;
            if let Some(seq) = &at.sequence {
                write_simple_element(w, "DefaultSequence", seq)?;
            }
            w.write(WXmlEvent::end_element())?;
        }

        if self.history.len() > 0 {
            w.write(WXmlEvent::start_element("History"))?;
            for history_item in &self.history {
                history_item.serialize(w, encryptor)?;
            }
            w.write(WXmlEvent::end_element())?;
        }

        let start =
            chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .timestamp();
        w.write(WXmlEvent::start_element("Times"))?;
        for (key, value) in &self.times {
            let mut ts_bytes = vec![];
            ts_bytes.write_i64::<LittleEndian>(value.timestamp() - start)?;
            w.write(WXmlEvent::start_element(key.as_str()))?;
            w.write(WXmlEvent::characters(base64::encode(ts_bytes).as_str()))?;
            w.write(WXmlEvent::end_element())?;
        }
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::end_element())?;
        Ok(())
    }
}
impl Serializable for Group {
    fn serialize<W: Write>(
        &self,
        w: &mut EventWriter<W>,
        encryptor: &mut dyn Cipher,
    ) -> WResult<()> {
        w.write(WXmlEvent::start_element("Group"))?;

        w.write(WXmlEvent::start_element("UUID"))?;
        w.write(WXmlEvent::characters(&self.uuid))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("Name"))?;
        w.write(WXmlEvent::characters(&self.name))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("Notes"))?;
        if self.notes.len() > 0 {
            w.write(WXmlEvent::characters(&self.notes))?;
        }
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("IconID"))?;
        w.write(WXmlEvent::characters(&self.icon_id.to_string()))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("IsExpanded"))?;
        w.write(WXmlEvent::characters(&self.is_expanded.to_string()))?;
        w.write(WXmlEvent::end_element())?;

        // FIXME
        w.write(WXmlEvent::start_element("DefaultAutoTypeSequence"))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("EnableAutoType"))?;
        let val = match &self.enable_auto_type {
            None => "null",
            Some(true) => "True",
            Some(false) => "False",
        };
        w.write(WXmlEvent::characters(&val))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("EnableSearching"))?;
        let val = match &self.enable_searching {
            None => "null",
            Some(true) => "True",
            Some(false) => "False",
        };
        w.write(WXmlEvent::characters(&val))?;
        w.write(WXmlEvent::end_element())?;

        w.write(WXmlEvent::start_element("LastTopVisibleGroup"))?;
        w.write(WXmlEvent::characters(
            &self.last_top_visible_entry.to_string(),
        ))?;
        w.write(WXmlEvent::end_element())?;

        let start =
            chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .timestamp();
        w.write(WXmlEvent::start_element("Times"))?;
        for (key, value) in &self.times {
            let mut ts_bytes = vec![];
            ts_bytes.write_i64::<LittleEndian>(value.timestamp() - start)?;
            w.write(WXmlEvent::start_element(key.as_str()))?;
            w.write(WXmlEvent::characters(base64::encode(ts_bytes).as_str()))?;
            w.write(WXmlEvent::end_element())?;
        }
        w.write(WXmlEvent::end_element())?;

        for node in &self.children {
            match node {
                DBNode::Group(g) => g.serialize(w, encryptor)?,
                DBNode::Entry(e) => e.serialize(w, encryptor)?,
            };
        }

        w.write(WXmlEvent::end_element())?;
        Ok(())
    }
}

impl Serializable for Database {
    fn serialize<W: Write>(
        &self,
        w: &mut EventWriter<W>,
        encryptor: &mut dyn Cipher,
    ) -> WResult<()> {
        w.write(WXmlEvent::start_element("KeePassFile"))?;
        self.meta.serialize(w, encryptor)?;
        w.write(WXmlEvent::start_element("Root"))?;
        self.root.serialize(w, encryptor)?;
        w.write(WXmlEvent::end_element())?;
        w.write(WXmlEvent::end_element())?;
        Ok(())
    }
}

fn parse_xml_timestamp(t: &str) -> Result<chrono::NaiveDateTime> {
    match chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%SZ") {
        // Prior to KDBX4 file format, timestamps were stored as ISO 8601 strings
        Ok(ndt) => Ok(ndt),
        // In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00
        // So, if we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
        _ => {
            let v = base64::decode(t).map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;
            // Cast the Vec created by base64::decode into the array expected by i64::from_le_bytes
            let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            a.copy_from_slice(&v[0..8]);
            let sec = i64::from_le_bytes(a);
            let ndt =
                chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                    .unwrap()
                    + chrono::Duration::seconds(sec);
            Ok(ndt)
        }
    }
}

pub(crate) fn write_xml(d: &Database, encryptor: &mut dyn Cipher) -> WResult<Vec<u8>> {
    let mut data = Vec::new();
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut data);

    d.serialize(&mut writer, encryptor).unwrap();
    Ok(data)
}

pub(crate) fn parse_xml_block(xml: &[u8], inner_cipher: &mut dyn Cipher) -> Result<(Group, Meta)> {
    // Result<Group, Option<Group>> {
    let parser = EventReader::new(xml);

    // Stack of parsed Node objects not yet associated with their parent
    let mut parsed_stack: Vec<Node> = vec![];

    // Stack of XML element names
    let mut xml_stack: Vec<String> = vec![];

    let mut root_group: Group = Default::default();
    let mut meta: Meta = Default::default();

    for e in parser {
        match e.unwrap() {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ref attributes,
                ..
            } => {
                xml_stack.push(local_name.clone());

                match &local_name[..] {
                    "Meta" => parsed_stack.push(Node::Meta(Default::default())),
                    "UUID" => parsed_stack.push(Node::UUID(String::new())),
                    "RecycleBinUUID" => parsed_stack.push(Node::RecycleBinUUID(String::new())),
                    "Group" => parsed_stack.push(Node::Group(Default::default())),
                    "Entry" => parsed_stack.push(Node::Entry(Default::default())),
                    "String" => parsed_stack.push(Node::KeyValue(
                        String::new(),
                        Value::Unprotected(String::new()),
                    )),
                    "Value" => {
                        // Are we encountering a protected value?
                        if attributes
                            .iter()
                            .find(|oa| oa.name.local_name == "Protected")
                            .map(|oa| &oa.value)
                            .map_or(false, |v| v.to_lowercase().parse::<bool>().unwrap_or(false))
                        {
                            // Transform value to a Value::Protected
                            if let Some(&mut Node::KeyValue(_, ref mut ev)) =
                                parsed_stack.last_mut()
                            {
                                *ev = Value::Protected(SecStr::new(vec![]));
                            }
                        }
                    }
                    "AutoType" => parsed_stack.push(Node::AutoType(Default::default())),
                    "Association" => {
                        parsed_stack.push(Node::AutoTypeAssociation(Default::default()))
                    }
                    "ExpiryTime" => parsed_stack.push(Node::ExpiryTime(String::new())),
                    "Expires" => parsed_stack.push(Node::Expires(bool::default())),
                    _ => {}
                }
            }

            XmlEvent::EndElement {
                name: OwnedName { ref local_name, .. },
            } => {
                xml_stack.pop();

                if [
                    "Group",
                    "Entry",
                    "String",
                    "AutoType",
                    "Association",
                    "ExpiryTime",
                    "Expires",
                    "Meta",
                    "RecycleBinUUID",
                    "UUID",
                ]
                .contains(&&local_name[..])
                {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry { ref mut fields, .. })) =
                                parsed_stack_head
                            {
                                // A KeyValue was finished inside of an Entry -> add a field
                                fields.insert(k, v);
                            }
                        }

                        Node::Group(finished_group) => {
                            match parsed_stack_head {
                                Some(&mut Node::Group(Group {
                                    ref mut children, ..
                                })) => {
                                    // A Group was finished - add Group to children
                                    children.push(crate::Node::Group(finished_group));
                                }
                                None => {
                                    // There is no more parent nodes left -> we are at the root
                                    root_group = finished_group;
                                }
                                _ => {}
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(&mut Node::Group(Group {
                                ref mut children, ..
                            })) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's children
                                children.push(crate::Node::Entry(finished_entry))
                            } else if let Some(&mut Node::Entry(Entry {
                                ref mut history, ..
                            })) = parsed_stack_head
                            {
                                //Entry nested in an Entry means we are working with History
                                history.push(finished_entry)
                            }
                        }

                        Node::AutoType(at) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut autotype, ..
                            })) = parsed_stack_head
                            {
                                autotype.replace(at);
                            }
                        }

                        Node::AutoTypeAssociation(ata) => {
                            if let Some(&mut Node::AutoType(AutoType {
                                ref mut associations,
                                ..
                            })) = parsed_stack_head
                            {
                                associations.push(ata);
                            }
                        }

                        Node::ExpiryTime(et) => {
                            // Currently ingoring any Err() from parse_xml_timestamp()
                            // Ignoring Err() to avoid possible regressions for existing users
                            if let Some(&mut Node::Entry(Entry { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            } else if let Some(&mut Node::Group(Group { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            }
                        }

                        Node::Expires(es) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            } else if let Some(&mut Node::Group(Group {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            }
                        }
                        Node::UUID(r) => match parsed_stack_head {
                            Some(&mut Node::Group(Group { ref mut uuid, .. })) => {
                                *uuid = r;
                            }
                            Some(&mut Node::Entry(Entry { ref mut uuid, .. })) => {
                                *uuid = r;
                            }
                            None => {}
                            _ => {}
                        },
                        Node::RecycleBinUUID(r) => {
                            if let Some(&mut Node::Meta(Meta {
                                ref mut recyclebin_uuid,
                                ..
                            })) = parsed_stack_head
                            {
                                *recyclebin_uuid = r;
                            }
                        }

                        Node::Meta(m) => {
                            meta = m;
                        }
                    }
                }
            }

            XmlEvent::Characters(c) => {
                // Got some character data that need to be matched to a Node on the parsed_stack.

                match (xml_stack.last().map(|s| &s[..]), parsed_stack.last_mut()) {
                    (Some("Name"), Some(&mut Node::Group(Group { ref mut name, .. }))) => {
                        // Got a "Name" element with a Node::Group on the parsed_stack
                        // Update the Group's name
                        *name = c;
                    }
                    (Some("ExpiryTime"), Some(&mut Node::ExpiryTime(ref mut et))) => {
                        *et = c;
                    }
                    (Some("Expires"), Some(&mut Node::Expires(ref mut es))) => {
                        *es = c == "True";
                    }
                    (Some("Key"), Some(&mut Node::KeyValue(ref mut k, _))) => {
                        // Got a "Key" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's key
                        *k = c;
                    }
                    (Some("Value"), Some(&mut Node::KeyValue(_, ref mut ev))) => {
                        // Got a "Value" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's value

                        match *ev {
                            Value::Bytes(_) => {} // not possible
                            Value::Unprotected(ref mut v) => {
                                *v = c;
                            }
                            Value::Protected(ref mut v) => {
                                // Use the decryptor to decrypt the protected
                                // and base64-encoded value
                                //
                                let buf = base64::decode(&c)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                let buf_decode = inner_cipher.decrypt(&buf)?;

                                let c_decode = std::str::from_utf8(&buf_decode)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    (Some("UUID"), Some(&mut Node::UUID(ref mut et))) => {
                        *et = c;
                    }
                    (Some("RecycleBinUUID"), Some(&mut Node::RecycleBinUUID(ref mut et))) => {
                        *et = c;
                    }
                    (Some("Enabled"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.enabled = c.parse().unwrap_or(false);
                    }
                    (Some("DefaultSequence"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.sequence = Some(c.to_owned());
                    }
                    (Some("Window"), Some(&mut Node::AutoTypeAssociation(ref mut ata))) => {
                        ata.window = Some(c.to_owned());
                    }
                    (
                        Some("KeystrokeSequence"),
                        Some(&mut Node::AutoTypeAssociation(ref mut ata)),
                    ) => {
                        ata.sequence = Some(c.to_owned());
                    }
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok((root_group, meta))
}
