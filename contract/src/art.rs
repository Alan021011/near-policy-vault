//! M26: the vault NFT draws itself. `nft_token` and the enumeration methods return, as the token's
//! `media`, an SVG card built from the vault's current state (its number, Ethereum address, daily
//! limit, waiting time, guardian, agent, NFT collections and whether a handover is open), so any
//! NEAR wallet shows the vault's rules without this project's web page. Nothing is stored: the
//! image is computed on every read, so it changes as soon as the rules change.

/// What the card shows. Plain values, so the drawing is pure and unit-testable.
pub struct VaultCard<'a> {
    pub token_id: &'a str,
    pub evm_address: Option<&'a str>,
    pub chain_id: u64,
    /// `None`: the vault has no rules yet (it cannot sign anything).
    pub rules: Option<CardRules<'a>>,
    pub handover_open: bool,
    pub signing: bool,
}

pub struct CardRules<'a> {
    pub eth_daily_cap_wei: u128,
    pub delay_ms: u64,
    pub guardian: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub nft_collections: usize,
    pub tokens: usize,
}

const MINT: &str = "#00EC97";
const AMBER: &str = "#F59E0B";
const MUTED: &str = "#94A3B8";

/// The image as a `data:` URI (percent-encoded SVG), ready for `TokenMetadata.media`.
pub fn vault_media(card: &VaultCard) -> String {
    format!("data:image/svg+xml;charset=utf-8,{}", percent_encode(&vault_svg(card)))
}

/// The SVG card. Every dynamic text goes through `xml_escape`.
pub fn vault_svg(c: &VaultCard) -> String {
    let (status, status_color) = if c.signing {
        ("SIGNING", AMBER)
    } else if c.handover_open {
        ("HANDOVER OPEN", AMBER)
    } else if c.rules.is_some() {
        ("RULES ACTIVE", MINT)
    } else {
        ("NO RULES YET", MUTED)
    };
    let address = c.evm_address.map(short_address).unwrap_or_else(|| "address pending".into());
    let mut rows: Vec<(String, String, bool)> = Vec::new();
    match &c.rules {
        Some(r) => {
            rows.push(("Daily limit".into(), format!("{} ETH", eth(r.eth_daily_cap_wei)), true));
            rows.push(("Waiting time".into(), duration(r.delay_ms), r.delay_ms > 0));
            rows.push(("Guardian".into(), r.guardian.map(|g| clip(g, 30)).unwrap_or_else(|| "none".into()), r.guardian.is_some()));
            rows.push(("AI agent".into(), r.agent.map(|a| clip(a, 30)).unwrap_or_else(|| "none".into()), true));
            if r.nft_collections > 0 || r.tokens > 0 {
                rows.push(("Also allowed".into(), format!("{} token(s), {} NFT collection(s)", r.tokens, r.nft_collections), true));
            }
        }
        None => rows.push(("Rules".into(), "none: it cannot pay anything".into(), false)),
    }
    let mut body = String::new();
    for (i, (label, value, ok)) in rows.iter().enumerate() {
        let y = 196 + i as u32 * 34;
        let mark = if *ok { MINT } else { AMBER };
        body.push_str(&format!(
            "<circle cx='34' cy='{cy}' r='4' fill='{mark}'/><text x='48' y='{y}' fill='{MUTED}' font-size='13'>{l}</text><text x='376' y='{y}' fill='#E2E1ED' font-size='14' font-family='monospace' text-anchor='end'>{v}</text>",
            cy = y - 4,
            l = xml_escape(label),
            v = xml_escape(value),
        ));
    }
    let chain = match c.chain_id {
        1 => "Ethereum".to_string(),
        11155111 => "Sepolia".to_string(),
        n => format!("chain {n}"),
    };
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 400' width='400' height='400' font-family='Helvetica,Arial,sans-serif'>\
<rect width='400' height='400' fill='#090A0F'/>\
<rect x='12' y='12' width='376' height='376' rx='10' fill='#0D0F17' stroke='#1E2333'/>\
<text x='28' y='48' fill='{MINT}' font-size='12' font-family='monospace' letter-spacing='2'>POLICY VAULT</text>\
<text x='28' y='92' fill='#E2E1ED' font-size='34' font-weight='700'>Vault #{id}</text>\
<text x='28' y='120' fill='{MUTED}' font-size='14' font-family='monospace'>{addr} on {chain}</text>\
<rect x='28' y='136' width='{pw}' height='24' rx='4' fill='none' stroke='{status_color}'/>\
<text x='40' y='153' fill='{status_color}' font-size='12' font-family='monospace' letter-spacing='1'>{status}</text>\
{body}\
<line x1='28' y1='350' x2='372' y2='350' stroke='#1E2333'/>\
<text x='28' y='372' fill='{MUTED}' font-size='11'>Title deed of an Ethereum account. No single party holds its key.</text>\
</svg>",
        id = xml_escape(c.token_id),
        addr = xml_escape(&address),
        chain = chain,
        pw = 24 + status.len() as u32 * 8,
    )
}

fn short_address(a: &str) -> String {
    if a.len() > 12 { format!("{}…{}", &a[..6], &a[a.len() - 4..]) } else { a.to_string() }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max - 1).collect::<String>()) }
}

/// Wei as ETH with at most 6 decimals, trailing zeros removed (0.001, 0.0005, 1.5).
pub fn eth(wei: u128) -> String {
    const UNIT: u128 = 1_000_000_000_000_000_000;
    let whole = wei / UNIT;
    let micro = (wei % UNIT) / 1_000_000_000_000; // 6 decimals
    if micro == 0 {
        return whole.to_string();
    }
    let frac = format!("{micro:06}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0 => "none".into(),
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

pub fn xml_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '\'' => "&apos;".to_string(),
            '"' => "&quot;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Percent-encodes everything except unreserved characters, so the data URI is valid anywhere.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card<'a>(rules: Option<CardRules<'a>>) -> VaultCard<'a> {
        VaultCard {
            token_id: "78",
            evm_address: Some("0x9b1cd76dcdc367c4364441e28f936508be189ff0"),
            chain_id: 11155111,
            rules,
            handover_open: false,
            signing: false,
        }
    }

    fn rules<'a>() -> CardRules<'a> {
        CardRules {
            eth_daily_cap_wei: 1_000_000_000_000_000,
            delay_ms: 60_000,
            guardian: Some("cheapicon4328.testnet"),
            agent: Some("recv.alan-vault-2026.testnet"),
            nft_collections: 0,
            tokens: 0,
        }
    }

    #[test]
    fn the_card_shows_the_rules_in_plain_words() {
        let svg = vault_svg(&card(Some(rules())));
        for s in ["Vault #78", "0x9b1c…9ff0 on Sepolia", "RULES ACTIVE", "0.001 ETH", "60 s", "cheapicon4328.testnet", "recv.alan-vault-2026.testnet"] {
            assert!(svg.contains(s), "missing {s}");
        }
    }

    #[test]
    fn a_vault_without_rules_says_so() {
        let svg = vault_svg(&card(None));
        assert!(svg.contains("NO RULES YET") && svg.contains("it cannot pay anything"));
    }

    #[test]
    fn handover_and_signing_show_in_the_status() {
        let mut c = card(Some(rules()));
        c.handover_open = true;
        assert!(vault_svg(&c).contains("HANDOVER OPEN"));
        c.signing = true;
        assert!(vault_svg(&c).contains("SIGNING"));
    }

    #[test]
    fn eth_amounts_are_readable() {
        assert_eq!(eth(1_000_000_000_000_000), "0.001");
        assert_eq!(eth(500_000_000_000_000), "0.0005");
        assert_eq!(eth(1_500_000_000_000_000_000), "1.5");
        assert_eq!(eth(2_000_000_000_000_000_000), "2");
        assert_eq!(eth(1), "0");
        assert_eq!(eth(u128::MAX).split('.').next().unwrap().len(), 21);
    }

    #[test]
    fn text_cannot_break_out_of_the_svg() {
        let mut c = card(Some(rules()));
        c.token_id = "1'><script>alert(1)</script>";
        let svg = vault_svg(&c);
        assert!(!svg.contains("<script"));
        let media = vault_media(&c);
        assert!(media.starts_with("data:image/svg+xml;charset=utf-8,%3Csvg"));
        assert!(!media.contains('<') && !media.contains('\'') && !media.contains('"') && !media.contains(' '));
    }

    #[test]
    fn the_image_stays_small() {
        let mut r = rules();
        r.nft_collections = 32;
        r.tokens = 32;
        let media = vault_media(&card(Some(r)));
        assert!(media.len() < 6000, "{} bytes", media.len());
    }
}
