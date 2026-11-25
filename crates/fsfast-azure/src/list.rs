//! List Containers / List Blobs (with delimiter and prefix, paginated by
//! `NextMarker`).

use fsfast_core::{Error, Result};
use fsfast_engine::stats::OpKind;
use fsfast_http_transport::Method;

use crate::client::{Client, Query};
use crate::info::{BlobProps, ContainerProps, decode_name};
use crate::xml::Element;

/// One entry of a List Blobs page, in service order.
#[derive(Debug, Clone)]
pub enum ListEntry {
    /// A blob.
    Blob(Box<BlobProps>),
    /// A `BlobPrefix` (ends with the delimiter).
    Prefix(String),
}

/// One page of List Blobs.
#[derive(Debug, Default)]
pub struct BlobPage {
    /// Entries in service order.
    pub entries: Vec<ListEntry>,
    /// Marker of the next page.
    pub next_marker: Option<String>,
}

impl BlobPage {
    /// Parse a List Blobs response.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let root = Element::parse(body)?;
        if root.name != "EnumerationResults" {
            return Err(Error::protocol(format!(
                "unexpected List Blobs root element <{}>",
                root.name
            )));
        }
        let mut entries = Vec::new();
        if let Some(blobs) = root.child("Blobs") {
            for c in &blobs.children {
                match c.name {
                    "Blob" => entries.push(ListEntry::Blob(Box::new(BlobProps::from_xml(c)?))),
                    "BlobPrefix" => {
                        let n = c
                            .child("Name")
                            .ok_or_else(|| Error::protocol("BlobPrefix without Name"))?;
                        entries.push(ListEntry::Prefix(decode_name(n)));
                    }
                    _ => {}
                }
            }
        }
        Ok(BlobPage {
            entries,
            next_marker: root.child_nonempty("NextMarker").map(str::to_owned),
        })
    }
}

/// One page of List Containers.
#[derive(Debug, Default)]
pub struct ContainerPage {
    /// Containers.
    pub containers: Vec<ContainerProps>,
    /// Marker of the next page.
    pub next_marker: Option<String>,
}

impl ContainerPage {
    /// Parse a List Containers response.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let root = Element::parse(body)?;
        let mut containers = Vec::new();
        if let Some(cs) = root.child("Containers") {
            for c in cs.children_named("Container") {
                containers.push(ContainerProps::from_xml(c)?);
            }
        }
        Ok(ContainerPage {
            containers,
            next_marker: root.child_nonempty("NextMarker").map(str::to_owned),
        })
    }
}

/// Parameters of a List Blobs call.
#[derive(Debug, Clone, Default)]
pub struct ListBlobs<'a> {
    /// Container.
    pub container: &'a str,
    /// Name prefix.
    pub prefix: &'a str,
    /// Delimiter (`Some("/")` for one level).
    pub delimiter: Option<&'a str>,
    /// Include versions.
    pub versions: bool,
    /// Page size (`maxresults`).
    pub max_results: Option<u32>,
    /// fsfast path for errors.
    pub path: &'a str,
}

impl Client {
    /// Fetch one page of List Blobs.
    pub async fn list_blobs_page(
        &self,
        p: &ListBlobs<'_>,
        marker: Option<&str>,
    ) -> Result<BlobPage> {
        let include = if p.versions {
            "metadata,versions"
        } else {
            "metadata"
        };
        let max = p.max_results.map(|m| m.to_string());
        let q = Query::new()
            .with("restype", "container")
            .with("comp", "list")
            .with_opt("prefix", Some(p.prefix).filter(|s| !s.is_empty()))
            .with_opt("delimiter", p.delimiter)
            .with("include", include)
            .with_opt("marker", marker)
            .with_opt("maxresults", max.as_deref());
        let req = self
            .request(Method::GET, &self.container_url(p.container), &q)?
            .op(OpKind::List)
            .path(p.path.to_owned());
        self.execute(req, |r| async move {
            let path = r.path().to_owned();
            let body = r.bytes().await?;
            BlobPage::parse(&body).map_err(|e| e.with_path(path))
        })
        .await
    }

    /// All entries of a listing (follows `NextMarker`).
    pub async fn list_blobs_all(&self, p: &ListBlobs<'_>) -> Result<Vec<ListEntry>> {
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let page = self.list_blobs_page(p, marker.as_deref()).await?;
            out.extend(page.entries);
            match page.next_marker {
                Some(m) if Some(&m) != marker.as_ref() => marker = Some(m),
                _ => break,
            }
        }
        Ok(out)
    }

    /// All containers (with metadata).
    pub async fn list_containers_all(&self) -> Result<Vec<ContainerProps>> {
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let q = Query::new()
                .with("comp", "list")
                .with("include", "metadata")
                .with_opt("marker", marker.as_deref());
            let url = format!("{}/", self.endpoint);
            let req = self
                .request(Method::GET, &url, &q)?
                .op(OpKind::List)
                .path("");
            let page = self
                .execute(req, |r| async move {
                    let body = r.bytes().await?;
                    ContainerPage::parse(&body)
                })
                .await?;
            out.extend(page.containers);
            match page.next_marker {
                Some(m) if Some(&m) != marker.as_ref() => marker = Some(m),
                _ => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pages() {
        let body = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><EnumerationResults ServiceEndpoint="http://127.0.0.1:10000/devstoreaccount1" ContainerName="c"><Prefix/><Marker/><MaxResults>5000</MaxResults><Delimiter>/</Delimiter><Blobs><BlobPrefix><Name>a/</Name></BlobPrefix><Blob><Name>top</Name><Properties><Content-Length>1</Content-Length></Properties></Blob><Blob><Name Encoded="true">x%01y</Name><Properties><Content-Length>2</Content-Length></Properties></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>"#;
        let p = BlobPage::parse(body).unwrap();
        assert_eq!(p.entries.len(), 3);
        assert!(matches!(&p.entries[0], ListEntry::Prefix(n) if n == "a/"));
        assert!(matches!(&p.entries[1], ListEntry::Blob(b) if b.name == "top" && b.size == 1));
        assert!(matches!(&p.entries[2], ListEntry::Blob(b) if b.name == "x\u{1}y"));
        assert_eq!(p.next_marker.as_deref(), Some("m2"));

        let body = br#"<EnumerationResults><Containers><Container><Name>c1</Name><Properties><Etag>"0x1"</Etag></Properties></Container></Containers><NextMarker/></EnumerationResults>"#;
        let p = ContainerPage::parse(body).unwrap();
        assert_eq!(p.containers[0].name, "c1");
        assert_eq!(p.next_marker, None);
        assert!(BlobPage::parse(b"<Other/>").is_err());
    }
}
