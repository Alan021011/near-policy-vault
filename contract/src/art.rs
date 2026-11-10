//! M26: the vault NFT draws itself. `nft_token` and the enumeration methods return, as the token's
//! `media`, an SVG card built from the vault's current state (its number, Ethereum address, daily
//! limit, waiting time, guardian, agent, approved recipients and whether a change or a handover is
//! pending), so any NEAR wallet shows the vault's rules without this project's web page. Nothing is
//! stored: the image is computed on every read, so it changes as soon as the rules change.

/// What the card shows. Plain values, so the drawing is pure and unit-testable.
pub struct VaultCard<'a> {
    pub token_id: &'a str,
    pub evm_address: Option<&'a str>,
    /// `None`: no chain fixed yet (no signature and no rules).
    pub chain_id: Option<u64>,
    /// `None`: the vault has no rules yet (it cannot sign anything).
    pub rules: Option<CardRules<'a>>,
    pub handover_open: bool,
    pub signing: bool,
    pub change_pending: bool,
}

pub struct CardRules<'a> {
    pub eth_daily_cap_wei: u128,
    pub delay_ms: u64,
    pub guardian: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub destinations: usize,
    pub nft_collections: usize,
    pub tokens: usize,
}

const MINT: &str = "#00EC97";
const AMBER: &str = "#F59E0B";
const MUTED: &str = "#94A3B8";

/// The image as a `data:` URI (percent-encoded SVG), ready for `TokenMetadata.media`.
pub fn vault_media(card: &VaultCard) -> String {
    media_uri(&vault_svg(card))
}

pub fn media_uri(svg: &str) -> String {
    format!("data:image/svg+xml;charset=utf-8,{}", percent_encode(svg))
}

/// The SVG card. Every dynamic text goes through `xml_escape`.
pub fn vault_svg(c: &VaultCard) -> String {
    let (status, status_color) = if c.signing {
        ("SIGNING", AMBER)
    } else if c.handover_open {
        ("HANDOVER OPEN", AMBER)
    } else if c.change_pending {
        ("RULE CHANGE PENDING", AMBER)
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
            rows.push(("Guardian".into(), r.guardian.map(account).unwrap_or_else(|| "none".into()), r.guardian.is_some()));
            rows.push(("AI agent".into(), r.agent.map(account).unwrap_or_else(|| "none".into()), true));
            rows.push(("Can pay".into(), count(r.destinations, "approved address", "approved addresses"), r.destinations > 0));
            if r.nft_collections > 0 || r.tokens > 0 {
                rows.push(("Also allowed".into(), format!("{} tokens · {} NFT sets", r.tokens, r.nft_collections), true));
            }
        }
        None => rows.push(("Rules".into(), "none: cannot pay".into(), false)),
    }
    // A transfer deletes the policy: the new owner starts with a locked vault and sets its own.
    if c.handover_open {
        rows.push(("After handover".into(), "rules reset".into(), false));
    }
    let mut body = String::new();
    for (i, (label, value, ok)) in rows.iter().enumerate() {
        let y = 190 + i as u32 * 24;
        let mark = if *ok { MINT } else { AMBER };
        body.push_str(&format!(
            "<circle cx='34' cy='{cy}' r='4' fill='{mark}'/><text x='48' y='{y}' fill='{MUTED}' font-size='12'>{l}</text><text x='376' y='{y}' fill='#E2E1ED' font-size='13' font-family='monospace' text-anchor='end'>{v}</text>",
            cy = y - 4,
            l = xml_escape(label),
            v = xml_escape(value),
        ));
    }
    let chain = match c.chain_id {
        Some(1) => "Ethereum".to_string(),
        Some(11155111) => "Sepolia".to_string(),
        Some(n) => clip_middle(&format!("chain {n}"), 18),
        None => "no chain yet".to_string(),
    };
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 400' width='400' height='400' font-family='Helvetica,Arial,sans-serif'>\
<rect width='400' height='400' fill='#090A0F'/>\
<rect x='12' y='12' width='376' height='376' rx='10' fill='#0D0F17' stroke='#1E2333'/>\
<text x='28' y='48' fill='{MINT}' font-size='12' font-family='monospace' letter-spacing='2'>POLICY VAULT</text>\
<text x='28' y='92' fill='#E2E1ED' font-size='34' font-weight='700'>Vault #{id}</text>\
<text x='28' y='120' fill='{MUTED}' font-size='14' font-family='monospace'>{addr} · {chain}</text>\
<rect x='28' y='136' width='{pw}' height='24' rx='4' fill='none' stroke='{status_color}'/>\
<text x='40' y='153' fill='{status_color}' font-size='12' font-family='monospace' letter-spacing='1'>{status}</text>\
{body}\
<line x1='28' y1='350' x2='372' y2='350' stroke='#1E2333'/>\
<text x='28' y='372' fill='{MUTED}' font-size='11'>Title deed of an Ethereum account. No single party holds its key.</text>\
</svg>",
        id = xml_escape(&clip_middle(c.token_id, 20)),
        addr = xml_escape(&address),
        chain = xml_escape(&chain),
        pw = 24 + status.len() as u32 * 8,
    )
}

fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        0 => "nobody yet".into(),
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

/// `0x9b1c…9ff0`; anything that is not a plain ASCII address is clipped safely instead.
fn short_address(a: &str) -> String {
    match (a.get(..6), a.get(a.len().saturating_sub(4)..)) {
        (Some(head), Some(tail)) if a.is_ascii() && a.len() > 12 => format!("{head}…{tail}"),
        _ => clip_middle(a, 14),
    }
}

/// Account ids up to 30 characters are shown whole; longer ones keep both ends, so two look-alike
/// names that differ at the end do not render the same.
fn account(s: &str) -> String {
    clip_middle(s, 30)
}

fn clip_middle(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let head = (max - 1) / 2;
    let tail = max - 1 - head;
    format!("{}…{}", chars[..head].iter().collect::<String>(), chars[chars.len() - tail..].iter().collect::<String>())
}

/// Wei as ETH with at most 6 decimals, trailing zeros removed (0.001, 0.0005, 1.5); a non-zero
/// amount below 0.000001 says so instead of showing 0.
pub fn eth(wei: u128) -> String {
    const UNIT: u128 = 1_000_000_000_000_000_000;
    let whole = wei / UNIT;
    let micro = (wei % UNIT) / 1_000_000_000_000; // 6 decimals
    if whole == 0 && micro == 0 && wei > 0 {
        return "<0.000001".into();
    }
    if micro == 0 {
        return whole.to_string();
    }
    let frac = format!("{micro:06}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// A waiting time, rounded up so it never looks shorter than it is.
fn duration(ms: u64) -> String {
    let up = |v: u64, d: u64| v.div_ceil(d);
    match ms {
        0 => "none".into(),
        ms if ms < 120_000 => format!("{} s", up(ms, 1000)),
        ms if ms < 7_200_000 => format!("{} min", up(ms, 60_000)),
        ms if ms < 259_200_000 => format!("{} h", up(ms, 3_600_000)),
        ms => format!("{} days", up(ms, 86_400_000)),
    }
}

pub fn xml_escape(s: &str) -> String {
    s.chars()
        // control characters and invisible direction marks could make a name look like another
        .filter(|c| !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'))
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
            chain_id: Some(11155111),
            rules,
            handover_open: false,
            signing: false,
            change_pending: false,
        }
    }

    fn rules<'a>() -> CardRules<'a> {
        CardRules {
            eth_daily_cap_wei: 1_000_000_000_000_000,
            delay_ms: 60_000,
            guardian: Some("cheapicon4328.testnet"),
            agent: Some("recv.alan-vault-2026.testnet"),
            destinations: 1,
            nft_collections: 0,
            tokens: 0,
        }
    }

    #[test]
    fn the_card_shows_the_rules_in_plain_words() {
        let svg = vault_svg(&card(Some(rules())));
        for s in ["Vault #78", "0x9b1c…9ff0 · Sepolia", "RULES ACTIVE", "0.001 ETH", "60 s", "cheapicon4328.testnet", "recv.alan-vault-2026.testnet", "1 approved address"] {
            assert!(svg.contains(s), "missing {s}");
        }
    }

    #[test]
    fn a_vault_without_rules_says_so() {
        let mut c = card(None);
        c.chain_id = None;
        let svg = vault_svg(&c);
        assert!(svg.contains("NO RULES YET") && svg.contains("none: cannot pay") && svg.contains("no chain yet"));
    }

    #[test]
    fn pending_changes_handover_and_signing_show_in_the_status() {
        let mut c = card(Some(rules()));
        c.change_pending = true;
        assert!(vault_svg(&c).contains("RULE CHANGE PENDING"));
        c.handover_open = true;
        let svg = vault_svg(&c);
        assert!(svg.contains("HANDOVER OPEN") && svg.contains("rules reset"), "a buyer must not think the rules come with the vault");
        c.signing = true;
        assert!(vault_svg(&c).contains("SIGNING"));
    }

    #[test]
    fn amounts_and_times_never_look_smaller_than_they_are() {
        assert_eq!(eth(1_000_000_000_000_000), "0.001");
        assert_eq!(eth(500_000_000_000_000), "0.0005");
        assert_eq!(eth(1_500_000_000_000_000_000), "1.5");
        assert_eq!(eth(2_000_000_000_000_000_000), "2");
        assert_eq!(eth(1), "<0.000001");
        assert_eq!(eth(0), "0");
        assert_eq!(eth(u128::MAX).split('.').next().unwrap().len(), 21);
        assert_eq!(duration(0), "none");
        assert_eq!(duration(999), "1 s");
        assert_eq!(duration(60_000), "60 s");
        assert_eq!(duration(259_199_000), "72 h");
        assert_eq!(duration(2 * 86_400_000 + 1), "49 h");
        assert_eq!(duration(3 * 86_400_000 + 1), "4 days");
    }

    #[test]
    fn look_alike_accounts_render_differently() {
        let a = account("guardian-of-my-company-treasury-number-one.testnet");
        let b = account("guardian-of-my-company-treasury-number-two.testnet");
        assert_ne!(a, b);
        assert!(a.chars().count() <= 30);
    }

    #[test]
    fn odd_strings_never_panic() {
        for s in ["", "é", "ééééééééééééééééé", "0x", "0x1234567890ab"] {
            let _ = short_address(s);
            let _ = clip_middle(s, 3);
        }
    }

    #[test]
    fn text_cannot_break_out_of_the_svg() {
        let mut c = card(Some(rules()));
        c.token_id = "1'><script>alert(1)</script>\u{0}\u{202e}";
        let svg = vault_svg(&c);
        assert!(!svg.contains("<script") && !svg.contains('\u{0}') && !svg.contains('\u{202e}'));
        let media = vault_media(&c);
        assert!(media.starts_with("data:image/svg+xml;charset=utf-8,%3Csvg"));
        assert!(!media.contains('<') && !media.contains('\'') && !media.contains('"') && !media.contains(' '));
    }

    #[test]
    fn the_image_stays_small() {
        let mut r = rules();
        r.nft_collections = 32;
        r.tokens = 32;
        r.destinations = 32;
        let mut c = card(Some(r));
        c.handover_open = true;
        let media = vault_media(&c);
        assert!(media.len() < 6000, "{} bytes", media.len());
    }
}
