use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type};

#[proc_macro_derive(TuiTable)]
pub fn table_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();
    let name = ast.ident;
    let mut fields = vec![];
    let mut header = vec![];
    let mut to_string = vec![];
    if let Data::Struct(data) = ast.data {
        if let Fields::Named(fields_named) = data.fields {
            for field in fields_named.named.iter() {
                if let Some(ident) = field.ident.clone() {
                    if !ident.to_string().starts_with("pad") {
                        header.push(ident.to_string());
                        fields.push((ident, field.ty.clone()));
                    }
                }
            }
        }
    }
    for (ident, ty) in fields {
        if let Type::Path(path) = ty {
            if path.path.is_ident("Ip") {
                to_string.push(quote!(
                    if self.family.is_ipv4() {
                        self.#ident.ipv4().to_string()
                    } else {
                        self.#ident.ipv6().to_string()
                    }
                ));
                continue;
            }
        }
        to_string.push(quote!(self.#ident.to_string()));
    }
    let output = quote!(
        impl #impl_generics ::tuitable::TuiTable for #name #ty_generics #where_clause {
        // impl #name {
            fn header() -> Vec<&'static str> {
                vec![
                    #(#header),*
                ]
            }

            fn row(&self) -> Vec<String> {
                vec![
                    #(#to_string),*
                ]
            }
        }
        unsafe impl ::plain::Plain for #name {}
    );
    output.into()
}
