use super::common::{common_validation, ValidationErr, VendorAttribute};
use super::PK11URIMapping;
use once_cell::sync::Lazy;
use regex::Regex;

#[cfg(debug_assertions)]
static PERCENT_ENCODING_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(%[a-f?A-F?\d?]{2})+$").expect("regex for percent-encoding validation")
});
#[cfg(debug_assertions)]
use super::common::maybe_suggest_percent_encoding;

static LIBRARY_VERSION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+(\.\d+){0,1}$").expect("regex for library-version validation"));

static SLOT_ID_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+$").expect("regex for slot-id validation"));

path_attributes!(
    token for "token",
    manufacturer for "manufacturer",
    serial for "serial",
    model for "model",
    library_manufacturer for "library-manufacturer",
    library_version for "library-version",
    library_description for "library-description",
    object for "object",
    r#type for "type",
    id for "id",
    slot_description for "slot-description",
    slot_manufacturer for "slot-manufacturer",
    slot_id for "slot-id"
);

impl<'a> PK11Attribute<'a> {
    fn validate(&self, value: &'a str) -> Result<(), ValidationErr> {
        match self {
            token(_)
            | manufacturer(_)
            | serial(_)
            | model(_)
            | library_manufacturer(_)
            | library_description(_)
            | object(_)
            | id(_)
            | slot_description(_)
            | slot_manufacturer(_)
            | VAttr(_) => {
                if let Some(validation_err) = common_validation(value) {
                    return Err(validation_err);
                }

                // ^^^ These path types must not have a '/' char in their value.
                // (however, the '/' is perfectly fine for query attribute values)
                if value.contains('/') {
                    return Err(ValidationErr {
                        violation: String::from("Invalid `pk11-pattr`: The general '/' delimiter must always be percent-encoded in a path component."),
                        help: format!("Replace `{value}` with `{fixed}`.", fixed=value.replace('/', "%2F"))
                    });
                }

                // If debug build, emit warning messages for RFC7512 "SHOULD" ... violations:
                #[cfg(debug_assertions)]
                if matches!(self, id(_)) && !PERCENT_ENCODING_REGEX.is_match(value) {
                    println!("pkcs11 warning: the whole value of the `id` attribute SHOULD be percent-encoded: id={value}.");
                } else {
                    const PK11_PATH_RES_AVAIL: [char; 1] = ['&'];
                    maybe_suggest_percent_encoding(self.to_str(), value, PK11_PATH_RES_AVAIL);
                }
            }
            r#type(_) => {
                if !["public", "private", "cert", "secret-key", "data"].contains(&value) {
                    return Err(ValidationErr {
                        violation: String::from(r#"Invalid `pk11-pattr`: `pk11-type` = `"type" "=" ( "public" / "private" / "cert" / "secret-key" / "data" )`."#),
                        help: format!("Replace `{value}` value with one of `public`, `private`, `cert`, `secret-key`, or `data`."),
                    });
                }
            }
            library_version(_) => {
                // Regex validation for `1*DIGIT [ "." 1*DIGIT ]`:
                if !LIBRARY_VERSION_REGEX.is_match(value) {
                    return Err(ValidationErr{
                        violation: String::from(r#"Invalid `pk11-pattr`: `pk11-lib-ver` = `"library-version" "=" 1*DIGIT [ "." 1*DIGIT ]`."#),
                        help: String::from("The `library-version` attribute represents the major and minor version decimal \
                        number of the library and its format is `M.N`. The major version is required."),
                    });
                }
            }
            slot_id(_) => {
                // Regex validation for `1*DIGIT`:
                if !SLOT_ID_REGEX.is_match(value) {
                    return Err(ValidationErr {
                        violation: String::from(
                            r#"Invalid `pk11-pattr`: `pk11-slot-id` = `"slot-id" "=" 1*DIGIT`."#,
                        ),
                        help: String::from("The `slot-id` value may only be numeric."),
                    });
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn assign<'a>(
    pk11_pattr: &'a str,
    mapping: &mut PK11URIMapping<'a>,
) -> Result<(), ValidationErr> {
    let PK11Attr { attr, value } = PK11Attr::try_from(pk11_pattr)?;
    attr.assign(value, mapping)
}
