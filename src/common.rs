/// A `parse` evaluation's most granular error, used
/// as the basis for building up error information
/// in order to feed details to larger contexts.
pub(crate) struct ValidationErr {
    pub(crate) violation: String,
    pub(crate) help: String,
}

#[cfg(feature = "validation")]
pub(crate) trait Validation<'a> {
    fn validate(&self, value: &'a str) -> Result<(), ValidationErr>;
}

#[cfg(all(debug_assertions, feature = "debug_warnings"))]
pub(crate) trait Warning<'a> {
    fn maybe_warn(&self, value: &'a str);
}

/// A "newtype" that encapsulates `1*pk11-v-attr-nm-char` vendor-specific
/// naming enforcement as well as verifying we don't allow standard
/// attribute naming collisions.  This is basically where everything that's
/// not a 1:1 spec match will fall through to and otherwise be verified as
/// "vendor-specific".
#[derive(Debug)]
pub(crate) struct VendorAttribute<'a>(pub(crate) &'a str);

#[cfg(feature = "validation")]
impl<'a> TryFrom<&'a str> for VendorAttribute<'a> {
    type Error = ValidationErr;

    fn try_from(vendor_attr: &'a str) -> Result<Self, Self::Error> {
        // Non-standard attribute name that happens to be empty?
        if vendor_attr.is_empty() {
            return Err(ValidationErr {
                violation: String::from("Invalid component: Missing attribute name."),
                help: String::from("The attribute name may not be blank. Refer to the RFC7512 specification for valid attributes."),
            });
        }

        // Misplaced path-component attribute?
        if [
            "token",
            "manufacturer",
            "serial",
            "model",
            "library-manufacturer",
            "library-version",
            "library-description",
            "object",
            "type",
            "id",
            "slot-description",
            "slot-manufacturer",
            "slot-id",
        ]
        .contains(&vendor_attr)
        {
            return Err(ValidationErr {
                violation: String::from("Naming collision with standard path component."),
                help: String::from("Move this attribute and its value to the PKCS#11 URI path."),
            });
        }
        // Misplaced query-component attribute?
        if ["pin-source", "pin-value", "module-name", "module-path"].contains(&vendor_attr) {
            return Err(ValidationErr {
                violation: String::from("Naming collision with standard query component."),
                help: format!("Move `{vendor_attr}` and its value to the PKCS#11 URI query."),
            });
        }
        // Validation rules for `1*pk11-v-attr-nm-char`:
        if !vendor_attr.chars().all(|v_attr_nm_char| {
            v_attr_nm_char.is_alphanumeric() || v_attr_nm_char == '-' || v_attr_nm_char == '_'
        }) {
            return Err(ValidationErr{
                violation: String::from("Invalid vendor-specific component name: expected `1*pk11-v-attr-nm-char`."),
                help: format!("`{vendor_attr}` violated vendor-specific attribute name characters consisting solely of alphanumeric, '-', or '_'.")
            });
        }

        #[cfg(debug_assertions)]
        if vendor_attr.starts_with("x-") {
            println!(
                r#"pkcs11 warning: per RFC7512, the previously used convention of starting vendor attributes with an "x-" prefix is now deprecated.  Identified: `{vendor_attr}`."#
            );
        }

        Ok(VendorAttribute(vendor_attr))
    }
}

#[cfg(not(feature = "validation"))]
impl<'a> From<&'a str> for VendorAttribute<'a> {

    fn from(vendor_attr: &'a str) -> Self {
        #[cfg(all(debug_assertions, feature = "debug_warnings"))]
        if vendor_attr.starts_with("x-") {
            println!(
                r#"pkcs11 warning: per RFC7512, the previously used convention of starting vendor attributes with an "x-" prefix is now deprecated.  Identified: `{vendor_attr}`."#
            );
        }

        VendorAttribute(vendor_attr)
    }
}

/// Values for *both* path and query components must not contain empty spaces or the '#' character.
#[cfg(feature = "validation")]
pub(crate) fn common_validation(value: &str) -> Option<ValidationErr> {
    if value.contains(' ') {
        return Some(ValidationErr {
            violation: String::from("Invalid component value: Appendix A of [RFC3986] specifies component values may not contain empty spaces."),
            help: format!("Replace `{value}` with `{fixed}`.", fixed=value.replace(' ', "%20"))
        });
    }

    if value.contains('#') {
        return Some(ValidationErr {
            violation: String::from(
                "Invalid component value: The '#' delimiter must always be percent-encoded.",
            ),
            help: format!(
                "Replace `{value}` with `{fixed}`.",
                fixed = value.replace('#', "%23")
            ),
        });
    }

    None
}

/// If running in a non-optimized build, this function will be utilized
/// to identify potential issues of unsupported characters.  The intent
/// of this function is to properly test attribute values in debug builds
/// and make appropriate changes for usage prior to release builds.
#[cfg(all(debug_assertions, feature = "debug_warnings"))]
pub(crate) fn maybe_suggest_percent_encoding<const T: usize>(
    attribute: &str,
    value: &str,
    addl_res_avail: [char; T], // additional reserved available
) {
    // refer to the RFC7512 specification for more details:
    const PK11_RES_AVAIL: [char; 17] = [
        '-', '.', '_', '~', ':', '[', ']', '@', '!', '$', '\'', '(', ')', '*', '+', ',', '=',
    ];
    let mut iter = value.chars().enumerate().peekable();
    while let Some((offset, value_char)) = iter.next() {
        match value_char {
            '%' => {
                // Emit warning if next two chars are not hexidecimal:
                if iter.next_if(|(_offset, c)| c.is_ascii_hexdigit()).is_none()
                    || iter.next_if(|(_offset, c)| c.is_ascii_hexdigit()).is_none()
                {
                    println!("pkcs11 warning: identified malformed percent-encoding at offset {offset} in \
                    `{value}` of component `{attribute}={value}`");
                }
            }
            c if c.is_alphanumeric()
                || PK11_RES_AVAIL.contains(&c)
                || addl_res_avail.contains(&c) => {}
            _ => {
                println!("pkcs11 warning: the `{value_char}` identified at offset {offset} in `{value}` of \
                component `{attribute}={value}` SHOULD be percent-encoded.");
            }
        }
    }
}
