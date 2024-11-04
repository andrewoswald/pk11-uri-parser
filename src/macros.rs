/// Simple helper to encapsulate attribute field access and provide method docs.
macro_rules! attr_access {
    ($fn_name:ident, $component:meta, $attr_name:literal) => {
        #[doc = "Retrieve the value of the"]
        #[doc = stringify!($attr_name)]
        #[$component]
        #[doc = "attribute if one was parsed."]
        pub fn $fn_name(&self) -> Option<&str> {
            self.$fn_name
        }
    };
    ($pattr_fn:ident for pk11-pattr $pattr_name:literal) => {
        attr_access!($pattr_fn, doc = "path", $pattr_name);
    };
    ($qattr_fn:ident for pk11-qattr $qattr_name:literal) => {
        attr_access!($qattr_fn, doc = "query", $qattr_name);
    };
}

/// Takes care of the boilerplate machinery for establishing PKCS#11
/// attribute enum values which then invoke a hand-coded `validate`
/// method to ensure the attribute's value aligns with the RFC7512
/// specification.  This is all pretty standard `try_from` with
/// error propagation type stuff.
macro_rules! pk11_attributes {
    { $( $name:ident for $text:literal),+ } => {
        struct PK11Attr<'a> {
            attr: PK11Attribute<'a>,
            value: &'a str
        }

        #[cfg(feature = "validation")]
        impl<'a> TryFrom<&'a str> for PK11Attr<'a> {
            type Error = ValidationErr;

            fn try_from(pk11_attr: &'a str) -> Result<Self, Self::Error> {
                // Intentionally *not* putting the empty check here
                // (and incurring its associated O(n) runtime cost);
                // the empty check gets handled further downstream if
                // the below "Malformed component." `ok_or` arm is invoked.
                let (attribute, value) = pk11_attr
                    .split_once('=')
                    .map(|(attribute, value)| (attribute.trim(), value.trim()))
                    .ok_or(ValidationErr {
                        violation: String::from("Malformed component."),
                        help: String::from("Please refer to RFC7512 for acceptable path|query attribute values."),
                    })?;

                let attr = PK11Attribute::try_from(attribute)?;

                // Implementation specific (hand-coded) callback:
                attr.validate(value)?;

                #[cfg(all(debug_assertions, feature = "debug_warnings"))]
                attr.maybe_warn(value);

                Ok(PK11Attr { attr, value })
            }
        }

        #[cfg(not(feature = "validation"))]
        impl<'a> From<&'a str> for PK11Attr<'a> {

            fn from(pk11_attr: &'a str) -> Self {
                // Intentionally *not* putting the empty check here
                // (and incurring its associated O(n) runtime cost);
                // the empty check gets handled further downstream if
                // the below "Malformed component." `ok_or` arm is invoked.
                let (attribute, value) = pk11_attr
                    .split_once('=')
                    .map(|(attribute, value)| (attribute.trim(), value.trim()))
                    .expect("attribute/value pair should be valid");

                let attr = PK11Attribute::from(attribute);

                #[cfg(all(debug_assertions, feature = "debug_warnings"))]
                attr.maybe_warn(value);

                PK11Attr { attr, value }
            }
        }

        use self::PK11Attribute::{$( $name),+, VAttr};

        #[allow(non_camel_case_types)]
        #[derive(Debug)]
        enum PK11Attribute<'a> {
            $( #[cfg(any(feature = "validation", all(debug_assertions, feature = "debug_warnings")))] $name(&'static str), )+
            $( #[cfg(not(any(feature = "validation", all(debug_assertions, feature = "debug_warnings"))))] $name(), )+
            VAttr(VendorAttribute<'a>),
        }

        #[cfg(feature = "validation")]
        impl <'a> TryFrom<&'a str> for PK11Attribute<'a> {
            type Error = ValidationErr;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                let attribute = match value {
                    // standard attribute names:
                    $( #[cfg(any(feature = "validation", all(debug_assertions, feature = "debug_warnings")))] $text => $name($text), )+
                    $( #[cfg(not(any(feature = "validation", all(debug_assertions, feature = "debug_warnings"))))] $text => $name(), )+
                    // non-standard: possibly a vendor-specific,
                    // misplaced standard, or empty attribute:
                    non_standard => VAttr(VendorAttribute::try_from(non_standard)?)
                };

                Ok(attribute)
            }
        }

        #[cfg(not(feature = "validation"))]
        impl <'a> From<&'a str> for PK11Attribute<'a> {
            fn from(value: &'a str) -> Self {
                match value {
                    // standard attribute names:
                    $( #[cfg(any(feature = "validation", all(debug_assertions, feature = "debug_warnings")))] $text => $name($text), )+
                    $( #[cfg(not(any(feature = "validation", all(debug_assertions, feature = "debug_warnings"))))] $text => $name(), )+
                    // non-standard:
                    non_standard => VAttr(VendorAttribute::from(non_standard))
                }
            }
        }

        impl <'a> PK11Attribute<'a> {

            // Used for warning messages:
            #[cfg(all(debug_assertions, feature = "debug_warnings"))]
            fn to_str(&self) -> &'a str {
                match self {
                    $( $name(name) => name, )+
                    VAttr(vendor_attribute) => vendor_attribute.0
                }
            }
        }
    };
}

/// In addition to establishing path enum variants and the boilerplate
/// code that potentially calls the `Validation` trait's `validate` method
/// and `Warning` trait's `maybe_warn` method, this macro provides the
/// `PK11PAttr` *assign* method.  The `assign` method implementation is
/// based on whether the `validation` feature has been enabled. The distinction
/// between path and query component assignment, assuming the `validation` feature
/// is enabled, is that while vendor-specific attributes may contain *multiple*
/// values, the *path* only allows distinct attribute names (no duplicates).
macro_rules! path_attributes {
    { $( $name:ident for $text:literal),+ } => {
        use PK11Attribute as PK11PAttr;
        use PK11Attr as PathAttribute;

        pk11_attributes!($( $name for $text),+ );

        impl <'a> PK11PAttr<'a> {
            #[cfg(feature = "validation")]
            fn assign(self, value: &'a str, mapping: &mut PK11URIMapping<'a>) -> Result<(), ValidationErr> {
                match self {
                    $( Self::$name(attribute) => {
                        if mapping.$name.is_none() {
                            mapping.$name = Some(value)
                        } else {
                            return Err(ValidationErr {
                                violation: format!(r#"Duplicate `pk11-pattr` standard name: "{attribute}"."#),
                                help: String::from("A PKCS #11 URI must not contain duplicate attributes of the same name in the URI path component.")
                            })
                        }
                    }, )+
                    VAttr(vendor_attribute) => {
                        if mapping.vendor.get(vendor_attribute.0).is_none() {
                            mapping.vendor.insert(vendor_attribute.0, vec![value]);
                        } else {
                            return Err(ValidationErr{
                                violation: format!(r#"Duplicate `pk11-v-pattr` vendor-specific name: "{}"."#, vendor_attribute.0),
                                help: String::from("A PKCS #11 URI must not contain duplicate vendor attributes of the same name in the URI path component.")
                            })
                        }
                    }
                }
                Ok(())
            }

            #[cfg(not(feature = "validation"))]
            fn assign(self, value: &'a str, mapping: &mut PK11URIMapping<'a>) -> Result<(), ValidationErr> {
                match self {
                    $( Self::$name(..) => {
                        mapping.$name = Some(value)
                    }, )+
                    VAttr(vendor_attribute) => {
                        mapping.vendor.insert(vendor_attribute.0, vec![value]);
                    }
                }
                Ok(())
            }
        }
    };
}

/// In addition to establishing query enum variants and the boilerplate
/// code that potentially calls the `Validation` trait's `validate` method
/// and `Warning` trait's `maybe_warn` method, this macro provides the
/// `PK11QAttr` *assign* method. The `assign` method implementation is
/// based on whether the `validation` feature has been enabled. Vendor-
/// specific attributes may accumulate *multiple* values when specified
/// in the query component.
macro_rules! query_attributes {
    { $( $name:ident for $text:literal),+ } => {
        use PK11Attribute as PK11QAttr;
        use PK11Attr as QueryAttribute;

        pk11_attributes!($( $name for $text),+ );

        impl <'a> PK11QAttr<'a> {
            #[cfg(feature = "validation")]
            fn assign(self, value: &'a str, mapping: &mut PK11URIMapping<'a>) -> Result<(), ValidationErr> {
                match self {
                    $( Self::$name(attribute) => {
                        if mapping.$name.is_none() {
                            mapping.$name = Some(value)
                        } else {
                            return Err(ValidationErr{
                                violation: format!(r#"Duplicate `pk11-qattr` standard name: "{attribute}"."#),
                                help: String::from("A PKCS #11 URI must not contain duplicate standard attributes of the same name in the URI query component.")
                            })
                        }
                    }, )+
                    VAttr(vendor_attribute) => mapping.vendor.entry(vendor_attribute.0).or_default().push(value)
                }
                Ok(())
            }

            #[cfg(not(feature = "validation"))]
            fn assign(self, value: &'a str, mapping: &mut PK11URIMapping<'a>) -> Result<(), ValidationErr> {
                match self {
                    $( Self::$name(..) => {
                        mapping.$name = Some(value)
                    }, )+
                    VAttr(vendor_attribute) => mapping.vendor.entry(vendor_attribute.0).or_default().push(value)
                }
                Ok(())
            }
        }
    };
}
