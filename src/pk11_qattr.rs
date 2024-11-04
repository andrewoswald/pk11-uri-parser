#[cfg(feature = "validation")]
use super::common::{common_validation, Validation};
use super::common::{ValidationErr, VendorAttribute};
use super::PK11URIMapping;

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
use super::common::{maybe_suggest_percent_encoding, Warning};

query_attributes!(
    pin_source for "pin-source",
    pin_value for "pin-value",
    module_name for "module-name",
    module_path for "module-path"
);

#[cfg(feature = "validation")]
impl<'a> Validation<'a> for PK11QAttr<'a> {
    fn validate(&self, value: &'a str) -> Result<(), ValidationErr> {
        if let Some(validation_err) = common_validation(value) {
            return Err(validation_err);
        }
        Ok(())
    }
}

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
impl<'a> Warning<'a> for PK11QAttr<'a> {
    fn maybe_warn(&self, value: &'a str) {
        if matches!(self, module_name(_))
            && (value.starts_with("lib") || value.chars().any(|c| ['.', '/', '\\'].contains(&c)))
        {
            println!(
                r#"pkcs11 warning: the attribute "module-name" SHOULD contain a case-insensitive PKCS #11 module name (not path nor filename) without system-specific affices. Context: `module-name={value}`."#
            );
        }
        // All query component values are `*pk11-qchar` so make a blanket call:
        const PK11_QUERY_RES_AVAIL: [char; 3] = ['/', '?', '|'];
        maybe_suggest_percent_encoding(self.to_str(), value, PK11_QUERY_RES_AVAIL);
    }
}

pub(crate) fn assign<'a>(
    pk11_qattr: &'a str,
    mapping: &mut PK11URIMapping<'a>,
) -> Result<(), ValidationErr> {
    #[cfg(feature = "validation")]
    let QueryAttribute { attr, value } = QueryAttribute::try_from(pk11_qattr)?;
    #[cfg(not(feature = "validation"))]
    let QueryAttribute { attr, value } = QueryAttribute::from(pk11_qattr);
    attr.assign(value, mapping)
}
