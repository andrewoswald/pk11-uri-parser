#[cfg(feature = "validation")]
use super::common::common_validation;
use super::common::{ValidationErr, VendorAttribute};
use super::PK11URIMapping;

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
use super::common::maybe_suggest_percent_encoding;

query_attributes!(
    pin_source for "pin-source",
    pin_value for "pin-value",
    module_name for "module-name",
    module_path for "module-path"
);

impl<'a> PK11QAttr<'a> {
    #[cfg(feature = "validation")]
    fn validate(&self, value: &'a str) -> Result<(), ValidationErr> {
        if let Some(validation_err) = common_validation(value) {
            return Err(validation_err);
        }

        // If debug build, emit warning messages for RFC7512 "SHOULD" ... violations:
        #[cfg(all(debug_assertions, feature = "debug_warnings"))]
        {
            if matches!(self, module_name(_))
                && (value.starts_with("lib")
                    || value.chars().any(|c| ['.', '/', '\\'].contains(&c)))
            {
                println!(
                    r#"pkcs11 warning: the attribute "module-name" SHOULD contain a case-insensitive PKCS #11 module name (not path nor filename) without system-specific affices. Context: `module-name={value}`."#
                );
            }
            // All query component values are `*pk11-qchar` so make a blanket call:
            const PK11_QUERY_RES_AVAIL: [char; 3] = ['/', '?', '|'];
            maybe_suggest_percent_encoding(self.to_str(), value, PK11_QUERY_RES_AVAIL);
        }

        Ok(())
    }

    #[cfg(all(not(feature = "validation"), all(debug_assertions, feature = "debug_warnings")))]
    fn validate(&self, value: &'a str) -> Result<(), ValidationErr> {
        // If debug build, emit warning messages for RFC7512 "SHOULD" ... violations:
        #[cfg(all(debug_assertions, feature = "debug_warnings"))]
        {
            if matches!(self, module_name(_))
                && (value.starts_with("lib")
                    || value.chars().any(|c| ['.', '/', '\\'].contains(&c)))
            {
                println!(
                    r#"pkcs11 warning: the attribute "module-name" SHOULD contain a case-insensitive PKCS #11 module name (not path nor filename) without system-specific affices. Context: `module-name={value}`."#
                );
            }
            // All query component values are `*pk11-qchar` so make a blanket call:
            const PK11_QUERY_RES_AVAIL: [char; 3] = ['/', '?', '|'];
            maybe_suggest_percent_encoding(self.to_str(), value, PK11_QUERY_RES_AVAIL);
        }

        Ok(())
    }
}

pub(crate) fn assign<'a>(
    pk11_qattr: &'a str,
    mapping: &mut PK11URIMapping<'a>,
) -> Result<(), ValidationErr> {
    #[cfg(feature = "validation")]
    let QueryAttribute{ attr, value } = QueryAttribute::try_from(pk11_qattr)?;
    #[cfg(not(feature = "validation"))]
    let QueryAttribute{ attr, value } = QueryAttribute::from(pk11_qattr);
    attr.assign(value, mapping)
}
