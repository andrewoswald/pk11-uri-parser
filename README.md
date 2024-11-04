# pk11-uri-parser

A *zero-copy* library to parse and validate PKCS#11 URIs in accordance to the [RFC7512](https://datatracker.ietf.org/doc/html/rfc7512) specification.

## Overview
Users of the library do not need to be intimately familiar with specification rules regarding what attributes belong to the path-component or the query-component, or to be knowledgeable about the various vendor-specific attribute rules.

A successfully parsed PKCS#11 URI will result in a `PK11URIMapping`: a simple struct with aptly named methods to directly access respective string slices (`&str`) of the given input.  Vendor-specific attribute values are made available through an intuitive `vendor` method which respectively provides `&Vec<&str>` also referring to `&str` from the input.  Parsing errors are reported by way of a `PK11URIError`, which offers a very user-friendly display as well as a help suggestion to resolve the issue. Lastly, *debug* builds provide "warning" messages when attribute values do not comply with the specification's "SHOULD"/"SHOULD NOT" guidelines (note: `--release` builds do **not** include the warning related code).

## Example
Pull in the lib:

```terminal
cargo add pk11-uri-parser
```
And run an example using a sample URI from the RFC7512 specification:

```rust,no_run
pub fn main() {
    let pk11_uri = "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;
            manufacturer=Snake%20Oil,%20Inc.;
            model=1.0;
            object=my-certificate;
            type=cert;
            id=%69%95%3E%5C%F4%BD%EC%91;
            serial=
            ?pin-source=file:/etc/token_pin";

    let mapping = pk11_uri_parser::parse(pk11_uri).expect("valid mapping");

    // access some standard attributes:
    assert_eq!(mapping.model(), Some("1.0"));
    assert_eq!(mapping.object(), Some("my-certificate"));
    assert_eq!(mapping.pin_source(), Some("file:/etc/token_pin"));
    // note: explicit empty string for serial:
    assert_eq!(mapping.serial(), Some(""));
    // note: "slot-id" not included so `None`:
    assert_eq!(mapping.slot_id(), None);
    // use the `vendor` method:
    assert_eq!(mapping.vendor("foo"), None);
}
```
## Errors
It's typical to do some exploration to become familiarized with how PKCS#11 URIs identify cryptographic assets.  This exploration is often* done using tools such as `p11tool` or `pkcs11-tool`, with the tool output being rather large (providing a great number of attribute/value pairs for a particular resource).  These tool-derived uris will certainly parse correctly, but a dramatically *shorter* uri will often end up being just as effective and will generally end up being more portable.  Likewise, it's out of scope for these tools to provide query-component attributes such as `pin-value` or `pin-source`.  As such, you may wish to experiment in discovering the shortest possible uri for your use-case.  This is where the `PK11URIError` will likely provide some assistance.

*(sometimes it's not, and you prefer some "YOLO" testing):\
Let's say you're attempting to use a YubiKey in order to use it for purposes of utilizing an HSM-bound private key.  According to the `Key Alias per Slot and Object Type` [documentation](https://developers.yubico.com/yubico-piv-tool/YKCS11/Functions_and_values.html), it may be worthwhile to try `pkcs11:slot=9e;object=Private key for Card Authentication;type=Private Key`:

```rust,no_run
pub fn main() -> Result<(), pk11_uri_parser::PK11URIError> {
    let pk11_uri = "pkcs11:slot=9e;object=Private key for Card Authentication;type=Private Key";

    let mapping = pk11_uri_parser::parse(pk11_uri)?;

    println!("mapping: {:?}", mapping);

    Ok(())
}
```
which results in
```terminal
Error: PK11URIError { pk11_uri: "pkcs11:slot=9e;object=Private key for Card Authentication;type=Private Key", error_span: (15, 57), violation: "Invalid component value: Appendix A of [RFC3986] specifies component values may not contain empty spaces.", help: "Replace `Private key for Card Authentication` with `Private%20key%20for%20Card%20Authentication`." }
```
which is helpful, but it's kind of ugly.  Let's modify our source to showcase the `PK11URIError`'s `Display` capability:
```rust,no_run
pub fn main() {
    let pk11_uri = "pkcs11:slot=9e;object=Private key for Card Authentication;type=Private Key";

    match pk11_uri_parser::parse(pk11_uri) {
        Ok(mapping) => println!("mapping: {:?}", mapping),
        Err(err) => println!("{err}")
    }
}
```
results in
```terminal
pkcs11:slot=9e;object=Private key for Card Authentication;type=Private Key
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Invalid component value: Appendix A of [RFC3986] specifies component values may not contain empty spaces.

help: Replace `Private key for Card Authentication` with `Private%20key%20for%20Card%20Authentication`.
```
Ah, much better! And in a style Rust developers have become accustomed to.  Let's employ the suggestion provided by `help:` and try again:
```rust,no_run
pub fn main() {
    let pk11_uri = "pkcs11:slot=9e;object=Private%20key%20for%20Card%20Authentication;type=Private Key";

    match pk11_uri_parser::parse(pk11_uri) {
        Ok(mapping) => println!("mapping: {:?}", mapping),
        Err(err) => println!("{err}")
    }
}
```
results in
```terminal
pkcs11:slot=9e;object=Private%20key%20for%20Card%20Authentication;type=Private Key
                                                                  ^^^^^^^^^^^^^^^^ Invalid `pk11-pattr`: `pk11-type` = `"type" "=" ( "public" / "private" / "cert" / "secret-key" / "data" )`.

help: Replace `Private Key` value with one of `public`, `private`, `cert`, `secret-key`, or `data`.
```
Another error.. which demonstrates that the `pk11-uri-parser` library will *fail-quickly* (ie, *short-circuit* further parsing) upon encountering an RFC7512 violation.

## Warnings
As previously noted, the RFC7512 specfication makes (*optional*) best-practice suggestions for attribute values by using terminology such as "SHOULD" and "SHOULD NOT".  The `pk11-uri-parser` library embraces these suggestions and when running under a `debug` build, will emit warning messages when such suggestion related criteria is met.  The messages begin with `pkcs11 warning:`.  It's important to note that warning related code is explicitly excluded from `--release` builds.
```rust,no_run
pub fn main() {
    let pk11_uri = "pkcs11:x-muppet=cookie<^^>monster!";
    let mapping = pk11_uri_parser::parse(pk11_uri).expect("valid mapping");
    let x_muppet = mapping.vendor("x-muppet").expect("valid vendor attribute");
    println!("`x-muppet` vendor value: {:?}", x_muppet);
}
```
prints
```terminal
pkcs11 warning: per RFC7512, the previously used convention of starting vendor attributes with an "x-" prefix is now deprecated.  Identified: `x-muppet`.
pkcs11 warning: the `<` identified at offset 6 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
pkcs11 warning: the `^` identified at offset 7 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
pkcs11 warning: the `^` identified at offset 8 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
pkcs11 warning: the `>` identified at offset 9 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
`x-muppet` vendor value: ["cookie<^^>monster!"]
```
## Vendor-specific Attributes

As showcased above, PKCS#11 URIs may contain "vendor-specific" attributes and that these vendor-specific attributes are allowed to have *multiple* values (thus the `&Vec<&str>` option return type for the `vendor` method).  It's worth pointing out that while vendor-specific attributes may have multiple values, the RFC7512 specfification does not allow duplicate *path-component* names, regardless of standard or vendor attribute.  A uri which contains duplicate path-component names will result in a `PK11URIError`.  Nevertheless, here's an example of a vendor-specific attribute which contains multiple values:
```rust,no_run
pub fn main() {
    let pk11_uri = "pkcs11:NATO=alpha?NATO=bravo&NATO=charlie";
    let mapping = pk11_uri_parser::parse(pk11_uri).expect("valid mapping");
    let nato = mapping.vendor("NATO").expect("valid vendor attribute");
    println!("`NATO` vendor value: {:?}", nato);
}
```
prints
```terminal
`NATO` vendor value: ["alpha", "bravo", "charlie"]
```

## Crate feature flags

At your disposal is the fine-grained control over validtion and debug warnings.  The default feature set it to *always* perform validation
and to provide `pkcs11 warning:` messages when debug build attribute values do not comply with RFC7512 "SHOULD/SHOULD NOT" guidelines.  To
do away with the default, simply assign `default-features=false` in your pk11-uri-parser dependency stanza. Please be aware, however, that doing
so will introduce `expect("my expectation")` calls required in the parsing logic.  See the [Cargo.toml](Cargo.toml) file for more details.

## License
This project's source code and documentation are licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
