#[cfg(feature = "validation")]
use super::common::{common_validation, Validation};
use super::common::{ValidationErr, VendorAttribute};
use super::PK11URIMapping;
#[cfg(any(
    feature = "validation",
    all(debug_assertions, feature = "debug_warnings")
))]
use once_cell::sync::Lazy;
#[cfg(any(
    feature = "validation",
    all(debug_assertions, feature = "debug_warnings")
))]
use regex::Regex;

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
use super::common::{maybe_suggest_percent_encoding, Warning};
#[cfg(all(debug_assertions, feature = "debug_warnings"))]
static PERCENT_ENCODING_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(%[a-f?A-F?\d?]{2})+$").expect("regex for percent-encoding validation")
});

#[cfg(feature = "validation")]
static LIBRARY_VERSION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+(\.\d+){0,1}$").expect("regex for library-version validation"));

#[cfg(feature = "validation")]
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

#[cfg(feature = "validation")]
impl<'a> Validation<'a> for PK11PAttr<'a> {
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

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
impl<'a> Warning<'a> for PK11PAttr<'a> {
    fn maybe_warn(&self, value: &'a str) {
        match self {
            id(_) => {
                if !PERCENT_ENCODING_REGEX.is_match(value) {
                    println!("pkcs11 warning: the whole value of the `id` attribute SHOULD be percent-encoded: id={value}.");
                }
            }
            token(_)
            | manufacturer(_)
            | serial(_)
            | model(_)
            | library_manufacturer(_)
            | library_description(_)
            | object(_)
            | slot_description(_)
            | slot_manufacturer(_)
            | VAttr(_) => {
                const PK11_PATH_RES_AVAIL: [char; 1] = ['&'];
                maybe_suggest_percent_encoding(self.to_str(), value, PK11_PATH_RES_AVAIL);
            }
            _ => {}
        }
    }
}

pub(crate) fn assign<'a>(
    pk11_pattr: &'a str,
    mapping: &mut PK11URIMapping<'a>,
) -> Result<(), ValidationErr> {
    #[cfg(feature = "validation")]
    let PathAttribute { attr, value } = PathAttribute::try_from(pk11_pattr)?;
    #[cfg(not(feature = "validation"))]
    let PathAttribute { attr, value } = PathAttribute::from(pk11_pattr);
    attr.assign(value, mapping)
}
