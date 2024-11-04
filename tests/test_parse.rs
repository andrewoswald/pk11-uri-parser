use pk11_uri_parser::parse;

/// All example PKCS#11 URI samples from the
/// RFC7512 specification should properly parse.
#[test]
fn spec_examples_all_parse() {
    let pk11_uri = "pkcs11:";
    parse(pk11_uri).expect("mapping should be valid");

    let pk11_uri = "pkcs11:object=my-pubkey;type=public";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.object(), Some("my-pubkey"));
    assert_eq!(mapping.r#type(), Some("public"));

    let pk11_uri = "pkcs11:object=my-key;type=private?pin-source=file:/etc/token";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.object(), Some("my-key"));
    assert_eq!(mapping.r#type(), Some("private"));
    assert_eq!(mapping.pin_source(), Some("file:/etc/token"));

    let pk11_uri = "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;
            manufacturer=Snake%20Oil,%20Inc.;
            model=1.0;
            object=my-certificate;
            type=cert;
            id=%69%95%3E%5C%F4%BD%EC%91;
            serial=
            ?pin-source=file:/etc/token_pin";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("The%20Software%20PKCS%2311%20Softtoken"));
    assert_eq!(mapping.manufacturer(), Some("Snake%20Oil,%20Inc."));
    assert_eq!(mapping.model(), Some("1.0"));
    assert_eq!(mapping.object(), Some("my-certificate"));
    assert_eq!(mapping.r#type(), Some("cert"));
    assert_eq!(mapping.id(), Some("%69%95%3E%5C%F4%BD%EC%91"));
    assert_eq!(mapping.serial(), Some(""));
    assert_eq!(mapping.pin_source(), Some("file:/etc/token_pin"));

    let pk11_uri = "pkcs11:object=my-sign-key;
            type=private
            ?module-name=mypkcs11";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.object(), Some("my-sign-key"));
    assert_eq!(mapping.r#type(), Some("private"));
    assert_eq!(mapping.module_name(), Some("mypkcs11"));

    let pk11_uri = "pkcs11:object=my-sign-key;
            type=private
            ?module-path=/mnt/libmypkcs11.so.1";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.object(), Some("my-sign-key"));
    assert_eq!(mapping.r#type(), Some("private"));
    assert_eq!(mapping.module_path(), Some("/mnt/libmypkcs11.so.1"));

    let pk11_uri = "pkcs11:token=Software%20PKCS%2311%20softtoken;
            manufacturer=Snake%20Oil,%20Inc.
            ?pin-value=the-pin";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("Software%20PKCS%2311%20softtoken"));
    assert_eq!(mapping.manufacturer(), Some("Snake%20Oil,%20Inc."));
    assert_eq!(mapping.pin_value(), Some("the-pin"));

    let pk11_uri = "pkcs11:slot-description=Sun%20Metaslot";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.slot_description(), Some("Sun%20Metaslot"));

    let pk11_uri = "pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;
            library-description=Soft%20Token%20Library;
            library-version=1.23";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.library_manufacturer(), Some("Snake%20Oil,%20Inc."));
    assert_eq!(mapping.library_description(), Some("Soft%20Token%20Library"));
    assert_eq!(mapping.library_version(), Some("1.23"));

    let pk11_uri = "pkcs11:token=My%20token%25%20created%20by%20Joe;
            library-version=3;
            id=%01%02%03%Ba%dd%Ca%fe%04%05%06";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("My%20token%25%20created%20by%20Joe"));
    assert_eq!(mapping.library_version(), Some("3"));
    assert_eq!(mapping.id(), Some("%01%02%03%Ba%dd%Ca%fe%04%05%06"));

    let pk11_uri = "pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;
            object=my-certificate;
            type=cert";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("A%20name%20with%20a%20substring%20%25%3B"));
    assert_eq!(mapping.object(), Some("my-certificate"));
    assert_eq!(mapping.r#type(), Some("cert"));

    let pk11_uri = "pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;
            object=my-certificate;
            type=cert";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1"));
    assert_eq!(mapping.object(), Some("my-certificate"));
    assert_eq!(mapping.r#type(), Some("cert"));

    let pk11_uri = "pkcs11:token=my-token;
            object=my-certificate;
            type=cert;
            vendor-aaa=value-a
            ?pin-source=file:/etc/token_pin
            &vendor-bbb=value-b";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.token(), Some("my-token"));
    assert_eq!(mapping.object(), Some("my-certificate"));
    assert_eq!(mapping.r#type(), Some("cert"));
    let vendor_aaa_value = mapping.vendor("vendor-aaa").expect("valid vendor-aaa value");
    assert!(vendor_aaa_value.eq(&vec!["value-a"]));
    assert_eq!(mapping.pin_source(), Some("file:/etc/token_pin"));
    let vendor_bbb_value = mapping.vendor("vendor-bbb").expect("valid vendor-bbb value");
    assert!(vendor_bbb_value.eq(&vec!["value-b"]));
}

/// Attributes whose values are text may not contain spaces.
#[test]
#[cfg(feature = "validation")]
fn text_values_with_empty_spaces_are_not_valid() {
    let pk11_uri = "pkcs11:token=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:manufacturer=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:serial=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:model=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:library-manufacturer=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:library-description=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:object=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:id=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:slot-description=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:slot-manufacturer=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:vendor-abc=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:pin-source=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:pin-value=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:module-name=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");

    let pk11_uri = "pkcs11:module-path=contains empty spaces";
    parse(pk11_uri).expect_err("empty space(s) in value should not be valid");
}

/// Attributes whose values are text may not contain the '#' char.
#[test]
#[cfg(feature = "validation")]
fn text_values_with_hash_char_are_not_valid() {
    let pk11_uri = "pkcs11:token=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:manufacturer=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:serial=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:model=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:library-manufacturer=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:library-description=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:object=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:id=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:slot-description=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:slot-manufacturer=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:vendor-abc=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:pin-source=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:pin-value=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:module-name=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");

    let pk11_uri = "pkcs11:module-path=contains#";
    parse(pk11_uri).expect_err("'#' in value should not be valid");
}

/// Path attributes whose value is text may not contain the '/' char.
#[test]
#[cfg(feature = "validation")]
fn path_text_values_with_backslash_not_valid() {
    let pk11_uri = "pkcs11:token=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:manufacturer=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:serial=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:model=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:library-manufacturer=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:library-description=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:object=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:id=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:slot-description=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:slot-manufacturer=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");

    let pk11_uri = "pkcs11:vendor-abc=foo/bar";
    parse(pk11_uri).expect_err("'/' in value should not be valid");
}

/// Attempting to use a standard query component attribute name
/// in the PKCS#11 URI path is not valid.
#[test]
#[cfg(feature = "validation")]
fn query_component_naming_collision_are_not_valid() {
    let pk11_uri = "pkcs11:pin-value=foo";
    parse(pk11_uri).expect_err("query component naming collision should not be valid");

    let pk11_uri = "pkcs11:pin-source=foo";
    parse(pk11_uri).expect_err("query component naming collision should not be valid");

    let pk11_uri = "pkcs11:module-name=foo";
    parse(pk11_uri).expect_err("query component naming collision should not be valid");

    let pk11_uri = "pkcs11:module-path=foo";
    parse(pk11_uri).expect_err("query component naming collision should not be valid");
}

/// Attempting to use a standard path component attribute name
/// in the PKCS#11 URI query is not valid.
#[test]
#[cfg(feature = "validation")]
fn path_component_naming_collision_are_not_valid() {
    let pk11_uri = "pkcs11:?token=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?manufacturer=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?serial=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?model=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?library-manufacturer=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?library-version=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?library-description=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?object=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?type=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?id=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?slot-description=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?slot-manufacturer=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");

    let pk11_uri = "pkcs11:?slot-id=foo";
    parse(pk11_uri).expect_err("path component naming collision should not be valid");
}

/// The `pk11-type` has values of "public", "private", "cert", "secret-key", and "data"
#[test]
fn type_has_finite_values() {
    let pk11_uri = "pkcs11:type=public";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.r#type(), Some("public"));

    let pk11_uri = "pkcs11:type=private";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.r#type(), Some("private"));

    let pk11_uri = "pkcs11:type=cert";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.r#type(), Some("cert"));

    let pk11_uri = "pkcs11:type=secret-key";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.r#type(), Some("secret-key"));

    let pk11_uri = "pkcs11:type=data";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.r#type(), Some("data"));
}

/// The `pk11-lib-ver` needs to be `1*DIGIT [ "." 1*DIGIT ]`
#[test]
#[cfg(feature = "validation")]
fn library_version_is_major_dot_minor() {
    let pk11_uri = "pkcs11:library-version=1";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.library_version(), Some("1"));

    let pk11_uri = "pkcs11:library-version=10";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.library_version(), Some("10"));

    let pk11_uri = "pkcs11:library-version=1.";
    parse(pk11_uri).expect_err("major dot nothing should not be valid");

    let pk11_uri = "pkcs11:library-version=1.0";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.library_version(), Some("1.0"));

    let pk11_uri = "pkcs11:library-version=1.01";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.library_version(), Some("1.01"));

    let pk11_uri = "pkcs11:library-version=SNAPSHOT";
    parse(pk11_uri).expect_err("non-numeric library version should not be valid");
}


/// The `pk11-slot-id` needs to be `1*DIGIT`
#[test]
#[cfg(feature = "validation")]
fn slot_id_needs_to_be_numeric() {
    let pk11_uri = "pkcs11:slot-id=1";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.slot_id(), Some("1"));

    let pk11_uri = "pkcs11:slot-id=123";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert_eq!(mapping.slot_id(), Some("123"));

    let pk11_uri = "pkcs11:slot-id=-123";
    parse(pk11_uri).expect_err("negative number should not be a valid slot-id value");

    let pk11_uri = "pkcs11:slot-id=foo";
    parse(pk11_uri).expect_err("non-numeric value should not be a valid slot-id value");
}

/// No exceptions to no duplicate path attribute names
#[test]
#[cfg(feature = "validation")]
fn duplicate_path_attributes_are_not_valid() {
    let pk11_uri = "pkcs11:token=foo;token=bar";
    parse(pk11_uri).expect_err("duplicate token attribute names should not be valid");

    let pk11_uri = "pkcs11:manufacturer=foo;manufacturer=bar";
    parse(pk11_uri).expect_err("duplicate manufacturer attribute names should not be valid");

    let pk11_uri = "pkcs11:serial=foo;serial=bar";
    parse(pk11_uri).expect_err("duplicate serial attribute names should not be valid");

    let pk11_uri = "pkcs11:model=foo;model=bar";
    parse(pk11_uri).expect_err("duplicate model attribute names should not be valid");

    let pk11_uri = "pkcs11:library-manufacturer=foo;library-manufacturer=bar";
    parse(pk11_uri).expect_err("duplicate library-manufacturer attribute names should not be valid");

    // note: library-version expects `1*DIGIT [ "." 1*DIGIT ]`
    let pk11_uri = "pkcs11:library-version=1;library-version=1.1";
    parse(pk11_uri).expect_err("duplicate library-manufacturer attribute names should not be valid");

    let pk11_uri = "pkcs11:library-description=foo;library-description=bar";
    parse(pk11_uri).expect_err("duplicate library-description attribute names should not be valid");

    let pk11_uri = "pkcs11:object=foo;object=bar";
    parse(pk11_uri).expect_err("duplicate object attribute names should not be valid");

    // note: type expects `( "public" / "private" / "cert" / "secret-key" / "data" )`
    let pk11_uri = "pkcs11:type=public;type=private";
    parse(pk11_uri).expect_err("duplicate type attribute names should not be valid");

    let pk11_uri = "pkcs11:id=foo;id=bar";
    parse(pk11_uri).expect_err("duplicate id attribute names should not be valid");

    let pk11_uri = "pkcs11:slot-description=foo;slot-description=bar";
    parse(pk11_uri).expect_err("duplicate slot-description attribute names should not be valid");

    let pk11_uri = "pkcs11:slot-manufacturer=foo;slot-manufacturer=bar";
    parse(pk11_uri).expect_err("duplicate slot-manufacturer attribute names should not be valid");

    // note: slot-id expects `1*DIGIT`
    let pk11_uri = "pkcs11:slot-id=123;slot-id=456";
    parse(pk11_uri).expect_err("duplicate slot-id attribute names should not be valid");

    let pk11_uri = "pkcs11:vendor-specific=foo;vendor-specific=bar";
    parse(pk11_uri).expect_err("duplicate vendor-specific *path* attribute names should not be valid");
}

/// Standard query attribute names may not appear more than
/// once in a PKCS#11 query.
#[test]
#[cfg(feature = "validation")]
fn duplicate_standard_query_attributes_are_not_allowed() {
    let pk11_uri = "pkcs11:?pin-source=foo&pin-source=bar";
    parse(pk11_uri).expect_err("duplicate pin-source attribute names should be not valid");

    let pk11_uri = "pkcs11:?pin-value=foo&pin-value=bar";
    parse(pk11_uri).expect_err("duplicate pin-value attribute names should be not valid");

    let pk11_uri = "pkcs11:?module-name=foo&module-name=bar";
    parse(pk11_uri).expect_err("duplicate module-name attribute names should be not valid");

    let pk11_uri = "pkcs11:?module-path=foo&module-path=bar";
    parse(pk11_uri).expect_err("duplicate module-path attribute names should be not valid");
}

/// Vendor-specific attributes may have multiple values.
/// Limited to a single path-component, but an arbitrary
/// number of query component entries.
#[test]
fn vendor_attributes_may_have_multiple_values() {
    let pk11_uri = "pkcs11:vendor-attribute=hello";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    assert!(mapping.vendor("vendor-attribute").expect("valid vendor-attribute value").eq(&vec!["hello"]));

    let pk11_uri = "pkcs11:vendor-attribute=hello?vendor-attribute=world";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    let vendor_attribute_value = mapping.vendor("vendor-attribute").expect("valid vendor-attribute value");
    assert!(vendor_attribute_value.eq(&vec!["hello", "world"]));

    let pk11_uri = "pkcs11:vendor-attribute=hello?
                            vendor-attribute=world&
                            vendor-attribute=foo&
                            vendor-attribute=bar";
    let mapping = parse(pk11_uri).expect("mapping should be valid");
    let vendor_attribute_value = mapping.vendor("vendor-attribute").expect("valid vendor-attribute value");
    assert!(vendor_attribute_value.eq(&vec!["hello", "world", "foo", "bar"]));
}
