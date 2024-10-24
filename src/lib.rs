//! A library to parse and validate PKCS#11 URIs in accordance to [RFC7512][rfc7512] specifications.
//!
//!
//!
//! [rfc7512]: <https://datatracker.ietf.org/doc/html/rfc7512>
//!
//! ## Examples
//!
//! Using a sample URI from the specification:
//! ```
//! use pk11_uri_parser::{parse, PK11URIError};
//!
//! fn main() -> Result<(), PK11URIError> {
//!     let pk11_uri = "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;
//!                            manufacturer=Snake%20Oil,%20Inc.;
//!                            model=1.0;
//!                            object=my-certificate;
//!                            type=cert;
//!                            id=%69%95%3E%5C%F4%BD%EC%91;
//!                            serial=
//!                            ?pin-source=file:/etc/token_pin";
//!
//!     let mapping = parse(pk11_uri)?;
//!
//!     println!("{:?}", mapping);
//!     Ok(())
//! }
//! ```
//! Will effectively print:
//! ```terminal
//! PK11URIMapping { token: Some("The%20Software%20PKCS%2311%20Softtoken"), manufacturer: Some("Snake%20Oil,%20Inc."), serial: Some(""), model: Some("1.0"), library_manufacturer: None, library_version: None, library_description: None, object: Some("my-certificate"), type: Some("cert"), id: Some("%69%95%3E%5C%F4%BD%EC%91"), slot_description: None, slot_manufacturer: None, slot_id: None, pin_source: Some("file:/etc/token_pin"), pin_value: None, module_name: None, module_path: None, vendor: {} }
//! ```
//!
//! The [parse] `Result`'s type is a [PK11URIMapping]. Users of the library do not need to be intimately
//! familiar with specification rules regarding what attributes belong to the path-component or the
//! query-component, or to be knowledgeable about the various vendor-specific attribute rules: the `PK11URIMapping`
//! provides appropriately named methods for retrieving standard component values and an intuitive
//! [vendor][`PK11URIMapping::vendor()`] method for retrieving *vendor-specific* attribute values.
//! ```
//! let pk11_uri = "pkcs11:vendor-attribute=my_vendor_attribte?pin-source=|/usr/lib/pinomatic";
//! let mapping = pk11_uri_parser::parse(pk11_uri).expect("mapping should be valid");
//! if let Some(pin_source) = mapping.pin_source() {
//!     // do something with `pin_source`...
//! }
//! // see whether we've got `vendor-attribute` values:
//! if let Some(vendor_values) = mapping.vendor("vendor-attribute") {
//!     // do something with `vendor_values`...
//! }
//! ```
//!
//! It's worth reiterating that vendor-specific attributes may have *multiple* values so therefore the `vendor`
//! method's `Option` return type is `&Vec<&'a str>`.
//!
//! ## Errors
//!
//! At least initially, PKCS#11 URIs will likely be derived from invoking exploratory commands in tools such as
//! `p11tool` or `pkcs11-tool`.  While parsing URIs from these tools is pretty much guaranteed to be successful,
//! it's often *not* necessary to provide such verbose values in order to properly identify your targeted resource.
//! It's also generally beyond the scope of those tools to include query-components (such as `pin-value` or `pin-source`).
//! In the interest of making your life a little bit easier (and code more readable), a bit of exploration can result
//! in a considerably shorter (and potentially more *portable*) URI.
//!
//! Let's say for example you are in need of utilizing an HSM-bound private key (and read "somewhere on the internet"):
//! ```
//! // note: this isn't a valid pkcs11 uri
//! let pk11_uri = "pkcs11:object=Private key for Card Authentication;pin-value=123456";
//! let err = pk11_uri_parser::parse(pk11_uri).expect_err("empty spaces in value violation");
//! println!("{:?}", err);
//! ```
//! Attempting to parse that uri will result in a [PK11URIError].
//! ```terminal
//! PK11URIError { pk11_uri: "pkcs11:object=Private key for Card Authentication;pin-value=123456", error_span: (7, 49), violation: "Invalid component value: Appendix A of [RFC3986] specifies component values may not contain empty spaces.", help: "Replace `Private key for Card Authentication` with `Private%20key%20for%20Card%20Authentication`." }
//! ```
//! Or if you'd prefer a fancier output, simply display the PK11URIError (*not* using `:?` debug):
//! ```
//! // note: this isn't a valid pkcs11 uri
//! let pk11_uri = "pkcs11:object=Private key for Card Authentication;pin-value=123456";
//! let err = pk11_uri_parser::parse(pk11_uri).expect_err("empty spaces in value violation");
//! println!("{err}");
//! ```
//! ```terminal
//! pkcs11:object=Private key for Card Authentication;pin-value=123456
//!        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Invalid component value: Appendix A of [RFC3986] specifies component values may not contain empty spaces.
//!
//! help: Replace `Private key for Card Authentication` with `Private%20key%20for%20Card%20Authentication`.
//! ```
//! Great!  Based on the "help" text, it's a simple fix:
//! ```
//! // note: again, this isn't a valid pkcs11 uri
//! let pk11_uri = "pkcs11:object=Private%20key%20for%20Card%20Authentication;pin-value=123456";
//! let err = pk11_uri_parser::parse(pk11_uri).expect_err("query component naming collision violation");
//! println!("{err}");
//! ```
//! This will once again fail to parse and brings up the fact that this library will *fail-quickly* (ie, short-circuit *further* parsing) if any violation is found.
//! ```terminal
//! pkcs11:object=Private%20key%20for%20Card%20Authentication;pin-value=123456
//!                                                           ^^^^^^^^^^^^^^^^ Naming collision with standard query component.
//!
//! help: Move `pin-value` and its value to the PKCS#11 URI query.
//! ```
//! In this case, `pin-value` is a standard *query-component* attribute name so its current location as a path attribute is a violation.
//! The "help" section again offers a simple solution.
//! ```no_run
//! let pk11_uri = "pkcs11:object=Private%20key%20for%20Card%20Authenciation?pin-value=123456";
//! pk11_uri_parser::parse(pk11_uri).expect("mapping should be valid");
//! ```
//! Which finally yields a valid mapping.
//!
//!  ## Warnings
//!
//! The [RFC7512][rfc7512] specification uses terminology such as `SHOULD` and `SHOULD NOT` to indicate *optional*,
//! best-practice type treatment for attribute values.  This library embraces these optional rules, but will only
//! emit *warning* messages to the terminal and only provide such warnings for *non-optimized* builds. Likewise,
//! violations of such optional rules will *never* result in a [PK11URIError]. The messages printed to the terminal
//! begin with `pkcs11 warning:`.
//!
//! Assuming a debug build:
//! ```no_run
//! let pk11_uri = "pkcs11:x-muppet=cookie<^^>monster!";
//! let mapping = pk11_uri_parser::parse(pk11_uri).expect("mapping should be valid");
//! let x_muppet = mapping.vendor("x-muppet").expect("valid x-muppet vendor-attribute");
//! println!("x-muppet: {:?}", x_muppet);
//! ```
//! prints
//! ```terminal
//! pkcs11 warning: per RFC7512, the previously used convention of starting vendor attributes with an "x-" prefix is now deprecated.  Identified: `x-muppet`.
//! pkcs11 warning: the `<` identified at offset 6 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
//! pkcs11 warning: the `^` identified at offset 7 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
//! pkcs11 warning: the `^` identified at offset 8 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
//! pkcs11 warning: the `>` identified at offset 9 in `cookie<^^>monster!` of component `x-muppet=cookie<^^>monster!` SHOULD be percent-encoded.
//! x-muppet: ["cookie<^^>monster!"]
//! ```
//! Any warning related code is explicitly **not** included in `--release` builds.

use std::collections::HashMap;
use std::fmt;

#[macro_use]
mod macros;

mod common;
mod pk11_pattr;
mod pk11_qattr;

const PKCS11_SCHEME: &str = "pkcs11:";
const PKCS11_SCHEME_LEN: usize = PKCS11_SCHEME.len();

/// Issued when [parsing][parse] a PKCS#11 URI is found to be in violation of [RFC7512][rfc7512] specifications.
///
/// The included `pk11_uri` is a "tidied" version of the one provided to the
/// `parse` function: any *newline* or *tab* formatting has been stripped out
/// in order to accurately identify the `error_span` within the uri. The `violation`
/// will refer to the [RFC7512 Augmented BNF][abnf] whenever possible, while the `help`
/// value provides a more human-friendly suggestion to correcting the violation.
///
/// [rfc7512]: <https://datatracker.ietf.org/doc/html/rfc7512>
/// [abnf]: <https://datatracker.ietf.org/doc/html/rfc7512#section-2.3>
#[derive(Debug)]
pub struct PK11URIError {
    /// The tidied uri identified as violating RFC7512.
    pk11_uri: String,
    /// The start end end offsets of the error.
    error_span: (usize, usize),
    /// The ABNF or RFC7512 text exhibiting the issue.
    violation: String,
    /// Human-friendly suggestion of how to resolve the issue.
    help: String,
}

/// Highlights the issue using the `error_span`.
impl fmt::Display for PK11URIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let padding = self.error_span.0;
        let highlight = self.error_span.1 - padding;
        write!(
            f,
            "{}\n{:padding$}{:^^highlight$} {violation}\n\nhelp: {help}",
            self.pk11_uri,
            "",
            "^",
            violation = self.violation,
            help = self.help
        )
    }
}

/// Encapsulates the result of successfully [parsing][parse] a PKCS#11 URI.
#[derive(Debug, Default, Clone)]
pub struct PK11URIMapping<'a> {
    // pk11-pattr:
    token: Option<&'a str>,
    manufacturer: Option<&'a str>,
    serial: Option<&'a str>,
    model: Option<&'a str>,
    library_manufacturer: Option<&'a str>,
    library_version: Option<&'a str>,
    library_description: Option<&'a str>,
    object: Option<&'a str>,
    r#type: Option<&'a str>,
    id: Option<&'a str>,
    slot_description: Option<&'a str>,
    slot_manufacturer: Option<&'a str>,
    slot_id: Option<&'a str>,
    // pk11-qattr:
    pin_source: Option<&'a str>,
    pin_value: Option<&'a str>,
    module_name: Option<&'a str>,
    module_path: Option<&'a str>,
    // vendor-specific:
    vendor: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> PK11URIMapping<'a> {
    // pk11-pattr:
    attr_access!(token for pk11-pattr "token");
    attr_access!(manufacturer for pk11-pattr "manufacturer");
    attr_access!(serial for pk11-pattr "serial");
    attr_access!(model for pk11-pattr "model");
    attr_access!(library_manufacturer for pk11-pattr "library-manufacturer");
    attr_access!(library_version for pk11-pattr "library-version");
    attr_access!(library_description for pk11-pattr "library-description");
    attr_access!(object for pk11-pattr "object");
    attr_access!(r#type for pk11-pattr "type");
    attr_access!(id for pk11-pattr "id");
    attr_access!(slot_description for pk11-pattr "slot-description");
    attr_access!(slot_manufacturer for pk11-pattr "slot-manufacturer");
    attr_access!(slot_id for pk11-pattr "slot-id");
    // pk11-qattr:
    attr_access!(pin_source for pk11-qattr "pin-source");
    attr_access!(pin_value for pk11-qattr "pin-value");
    attr_access!(module_name for pk11-qattr "module-name");
    attr_access!(module_path for pk11-qattr "module-path");
    // vendor-specific:
    /// Retrieve the `&Vec<&'a str>` values for the *vendor-specific* `vendor_attr` if parsed.
    ///
    /// ## Examples
    ///
    ///```
    /// // `v-attr` is an example "vendor-specific" attribute:
    /// let pk11_uri = "pkcs11:v-attr=val1?v-attr=val2&v-attr=val3";
    /// let mapping = pk11_uri_parser::parse(pk11_uri).expect("valid mapping");
    /// // Retrieve the `v-attr` values using the `vendor` method:
    /// let vendor_attrs = mapping.vendor("v-attr").expect("v-attr vendor-specific attribute values");
    /// for v_attr_val in vendor_attrs {
    ///     println!("{v_attr_val}")
    /// }
    /// ```
    /// prints
    /// ```terminal
    /// val1
    /// val2
    /// val3
    /// ```
    pub fn vendor(&self, vendor_attr: &str) -> Option<&Vec<&'a str>> {
        self.vendor.get(vendor_attr)
    }
}

/// Parses and verifies the contents of the given `pk11_uri` &str, making
/// parsed values available through a [PK11URIMapping]. Violations to [RFC7512][rfc7512]
/// specifications will result in issuing a [PK11URIError].
///
/// The contents of the `PK11URIMapping` are string slices of the `pk11_uri`,
/// so if you need the mapping to outlive the pk11_uri, simply clone it.
///
/// [rfc7512]: <https://datatracker.ietf.org/doc/html/rfc7512>
pub fn parse(pk11_uri: &str) -> Result<PK11URIMapping, PK11URIError> {
    if !pk11_uri.starts_with(PKCS11_SCHEME) {
        return Err(PK11URIError {
            pk11_uri: tidy(pk11_uri),
            error_span: (0, 0),
            violation: String::from(
                r#"Invalid `pk11-URI`: expected `"pkcs11:" pk11-path [ "?" pk11-query ]`."#,
            ),
            help: String::from("PKCS#11 URI must start with `pkcs11:`."),
        });
    }

    // Technically, a lone `pkcs11:` scheme is valid, so
    // we'll go ahead and create our default mapping now:
    let mut mapping = PK11URIMapping::default();

    let query_component_index = pk11_uri.find('?');

    // If we've got a `pk11-path`, attempt to assign its `pk11-pattr` values:
    if let Some(pk11_path) = pk11_uri
        .get(PKCS11_SCHEME_LEN..query_component_index.unwrap_or(pk11_uri.len()))
        .filter(|pk11_path| !pk11_path.is_empty())
    {
        pk11_path
            .split(';')
            .enumerate()
            .try_for_each(|(count, pk11_pattr)| {
                pk11_pattr::assign(pk11_pattr, &mut mapping).map_err(|validation_err| {
                    let tidy_pk11_uri = tidy(pk11_uri);
                    let tidy_pk11_path = tidy(pk11_path);
                    let tidy_pk11_pattr = tidy(pk11_pattr);

                    let mut violation = validation_err.violation;
                    let mut help = validation_err.help;

                    let error_start = if !tidy_pk11_pattr.is_empty() {
                        tidy_pk11_path.find(&tidy_pk11_pattr).unwrap()
                    } else {
                        // assign this here rather than adding O(n) runtime checks
                        // for basically an unlikely outlier type of error:
                        violation = String::from("Misplaced path delimiter.");
                        help = String::from("Remove the misplaced ';' delimiter.");
                        find_empty_attr_index(&tidy_pk11_path, count, ';')
                    } + PKCS11_SCHEME_LEN;
                    PK11URIError {
                        pk11_uri: tidy_pk11_uri,
                        error_span: (error_start, error_start + tidy_pk11_pattr.len()),
                        violation,
                        help,
                    }
                })
            })?;
    }

    // If we've got a `pk11-query`, attempt to assign its `pk11-qattr` values:
    if query_component_index.is_some() {
        // Assuming it's not empty, query component is from
        // the identified '?' to the remainder of the `pk11_uri`:
        if let Some(pk11_query) = pk11_uri
            .get(query_component_index.unwrap() + 1..)
            .filter(|pk11_query| !pk11_query.is_empty())
        {
            pk11_query
                .split('&')
                .enumerate()
                .try_for_each(|(count, pk11_qattr)| {
                    pk11_qattr::assign(pk11_qattr, &mut mapping).map_err(|validation_err| {
                        let tidy_pk11_uri = tidy(pk11_uri);
                        let tidy_pk11_query = tidy(pk11_query);
                        let tidy_pk11_qattr = tidy(pk11_qattr);

                        let mut violation = validation_err.violation;
                        let mut help = validation_err.help;

                        let error_start = if !tidy_pk11_qattr.is_empty() {
                            tidy_pk11_query.find(&tidy_pk11_qattr).unwrap()
                        } else {
                            // assign this here rather than adding O(n) runtime checks
                            // for basically an unlikely outlier type of error:
                            violation = String::from("Misplaced query delimiter.");
                            help = String::from("Remove the misplaced '&' delimiter.");
                            find_empty_attr_index(&tidy_pk11_query, count, '&')
                        } + tidy_pk11_uri.find('?').unwrap()
                            + 1;
                        PK11URIError {
                            pk11_uri: tidy_pk11_uri,
                            error_span: (error_start, error_start + tidy_pk11_qattr.len()),
                            violation,
                            help,
                        }
                    })
                })?;
        }

        // "...semantics of using both attributes in the same URI string is implementation specific
        //  but such use SHOULD be avoided.  Attribute "module-name" is preferred to "module-path" due
        //  to its system-independent nature, but the latter may be more suitable for development and debugging."
        #[cfg(debug_assertions)]
        if mapping.module_name.is_some() && mapping.module_path.is_some() {
            println!(
                "pkcs11 warning: using both `module-name` and `module-path` SHOULD be avoided. \
            Attribute `module-name` is preferred due to its system-independent nature."
            );
        }

        // "If a URI contains both "pin-source" and "pin-value" query attributes, the URI SHOULD be refused as invalid."
        #[cfg(debug_assertions)]
        if mapping.pin_source.is_some() && mapping.pin_value.is_some() {
            println!(
                r#"pkcs11 warning: a PKCS#11 URI containing both "pin-source" and "pin-value" query attributes SHOULD be refused as invalid."#
            );
        }
    }

    Ok(mapping)
}

/// Helper function to identify the location of an empty path|query component.
/// An empty component is a phenomena of a superfluous ';' or '&' delimiter such
/// as `pkcs11:foo=bar;`
///                   ^ trailing ';' is a RFC7512 violation.
fn find_empty_attr_index(tidy_attr: &str, split_count: usize, delimiter: char) -> usize {
    tidy_attr
        .match_indices(delimiter)
        .nth(split_count)
        .unwrap_or((tidy_attr.len() - 1, "_"))
        .0
}

/// Establish the basis for reliable error reporting by removing '\n' newline
/// and '\t' tab formatting.
fn tidy(maybe_messy: &str) -> String {
    maybe_messy.replace(['\n', '\t'], "")
}
