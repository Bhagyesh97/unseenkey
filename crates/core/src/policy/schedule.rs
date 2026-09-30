//! Time windows: `"Mon-Fri 09:00-19:00"` in an IANA time zone.

use super::PolicyError;
use serde::{Deserialize, Serialize};

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// One window: a set of weekdays and a time range (end exclusive, `24:00` allowed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Window {
    /// Bit `i` set = day `i` (Mon = 0).
    pub days: u8,
    /// Minutes since midnight, inclusive.
    pub start: u16,
    /// Minutes since midnight, exclusive.
    pub end: u16,
    text: String,
}

fn day_index(s: &str) -> Option<u8> {
    DAYS.iter()
        .position(|d| d.eq_ignore_ascii_case(s))
        .map(|i| i as u8)
}

fn parse_time(s: &str) -> Option<u16> {
    let (h, m) = s.split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if m > 59 || h > 24 || (h == 24 && m != 0) {
        return None;
    }
    Some(h * 60 + m)
}

impl Window {
    /// Parse `"Mon-Fri 09:00-19:00"`, `"Sat,Sun 10:00-12:00"`, `"Fri-Mon 00:00-24:00"`.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let err = |m: &str| PolicyError::Window(s.to_string(), m.to_string());
        let mut it = s.split_whitespace();
        let (days_spec, time_spec) = match (it.next(), it.next(), it.next()) {
            (Some(d), Some(t), None) => (d, t),
            _ => return Err(err("expected \"DAYS HH:MM-HH:MM\"")),
        };
        let mut days = 0u8;
        for part in days_spec.split(',') {
            if let Some((a, b)) = part.split_once('-') {
                let a = day_index(a).ok_or_else(|| err("unknown day"))?;
                let b = day_index(b).ok_or_else(|| err("unknown day"))?;
                let mut d = a;
                loop {
                    days |= 1 << d;
                    if d == b {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            } else {
                let d = day_index(part).ok_or_else(|| err("unknown day"))?;
                days |= 1 << d;
            }
        }
        let (start, end) = time_spec
            .split_once('-')
            .ok_or_else(|| err("expected HH:MM-HH:MM"))?;
        let start = parse_time(start).ok_or_else(|| err("bad start time"))?;
        let end = parse_time(end).ok_or_else(|| err("bad end time"))?;
        if end <= start {
            return Err(err(
                "end must be after start (split overnight windows in two)",
            ));
        }
        Ok(Self {
            days,
            start,
            end,
            text: s.trim().to_string(),
        })
    }

    /// Is (weekday, minute-of-day) inside the window?
    pub fn contains(&self, weekday: u8, minute: u16) -> bool {
        self.days & (1 << weekday) != 0 && minute >= self.start && minute < self.end
    }

    /// Original text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Human form: `Mon–Fri 09:00–19:00`.
    pub fn describe(&self) -> String {
        let mut names = Vec::new();
        for (i, d) in DAYS.iter().enumerate() {
            if self.days & (1 << i) != 0 {
                names.push(*d);
            }
        }
        let days = if names.len() == 7 {
            "every day".to_string()
        } else if names.len() >= 3 && contiguous(self.days) {
            format!("{}–{}", names[0], names[names.len() - 1])
        } else {
            names.join(", ")
        };
        format!(
            "{days} {:02}:{:02}–{:02}:{:02}",
            self.start / 60,
            self.start % 60,
            self.end / 60,
            self.end % 60
        )
    }
}

fn contiguous(bits: u8) -> bool {
    // A single run of ones in a 7-bit field (no wrap).
    let b = bits & 0x7f;
    if b == 0 {
        return false;
    }
    let shifted = b >> b.trailing_zeros();
    (shifted & (shifted + 1)) == 0
}

impl Serialize for Window {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for Window {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Window::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Allowed windows in a time zone. Outside every window the policy denies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// IANA zone, e.g. `Asia/Kolkata`, `UTC`.
    pub timezone: String,
    /// Windows; at least one.
    pub allowed: Vec<Window>,
}

impl Schedule {
    /// Check the zone exists and there is at least one window.
    pub fn validate(&self) -> Result<(), PolicyError> {
        jiff::tz::TimeZone::get(&self.timezone)
            .map_err(|_| PolicyError::TimeZone(self.timezone.clone()))?;
        if self.allowed.is_empty() {
            return Err(PolicyError::Invalid("schedule.allowed is empty".into()));
        }
        Ok(())
    }

    /// Is the instant inside any window? Unknown zones count as outside (deny).
    pub fn permits(&self, now_unix_ms: i64) -> bool {
        let Ok(tz) = jiff::tz::TimeZone::get(&self.timezone) else {
            return false;
        };
        let Ok(ts) = jiff::Timestamp::from_millisecond(now_unix_ms) else {
            return false;
        };
        let z = ts.to_zoned(tz);
        let weekday = match z.weekday() {
            jiff::civil::Weekday::Monday => 0,
            jiff::civil::Weekday::Tuesday => 1,
            jiff::civil::Weekday::Wednesday => 2,
            jiff::civil::Weekday::Thursday => 3,
            jiff::civil::Weekday::Friday => 4,
            jiff::civil::Weekday::Saturday => 5,
            jiff::civil::Weekday::Sunday => 6,
        };
        let minute = z.hour() as u16 * 60 + z.minute() as u16;
        self.allowed.iter().any(|w| w.contains(weekday, minute))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(rfc: &str) -> i64 {
        rfc.parse::<jiff::Timestamp>().unwrap().as_millisecond()
    }

    #[test]
    fn window_parse() {
        let w = Window::parse("Mon-Fri 09:00-19:00").unwrap();
        assert_eq!(w.days, 0b0001_1111);
        assert!(w.contains(0, 9 * 60));
        assert!(!w.contains(0, 19 * 60));
        assert!(!w.contains(5, 10 * 60));
        assert_eq!(w.describe(), "Mon–Fri 09:00–19:00");
        let w = Window::parse("Sat,Sun 10:00-12:30").unwrap();
        assert_eq!(w.days, 0b0110_0000);
        assert_eq!(w.describe(), "Sat, Sun 10:00–12:30");
        let w = Window::parse("Fri-Mon 00:00-24:00").unwrap();
        assert_eq!(w.days, 0b0111_0001);
        assert!(w.contains(6, 23 * 60 + 59));
        let w = Window::parse("Mon-Sun 00:00-24:00").unwrap();
        assert_eq!(w.describe(), "every day 00:00–24:00");
        for bad in [
            "Mon",
            "Mon 9-10",
            "Xyz 09:00-10:00",
            "Mon 10:00-09:00",
            "Mon 25:00-26:00",
        ] {
            assert!(Window::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn schedule_in_timezone_with_dst() {
        let s = Schedule {
            timezone: "America/New_York".into(),
            allowed: vec![Window::parse("Mon-Fri 09:00-17:00").unwrap()],
        };
        s.validate().unwrap();
        // Wednesday 2026-07-15 13:00 UTC = 09:00 EDT (UTC-4): inside.
        assert!(s.permits(ms("2026-07-15T13:00:00Z")));
        // 12:59 UTC = 08:59 EDT: outside.
        assert!(!s.permits(ms("2026-07-15T12:59:00Z")));
        // Wednesday 2026-01-14 13:00 UTC = 08:00 EST (UTC-5): outside.
        assert!(!s.permits(ms("2026-01-14T13:00:00Z")));
        assert!(s.permits(ms("2026-01-14T14:00:00Z")));
        // Saturday: outside.
        assert!(!s.permits(ms("2026-07-18T15:00:00Z")));
        let kolkata = Schedule {
            timezone: "Asia/Kolkata".into(),
            allowed: vec![Window::parse("Mon-Fri 09:00-19:00").unwrap()],
        };
        // 03:30 UTC = 09:00 IST on a Monday.
        assert!(kolkata.permits(ms("2026-07-13T03:30:00Z")));
        assert!(!kolkata.permits(ms("2026-07-13T03:29:00Z")));
    }

    #[test]
    fn bad_zone_is_invalid_and_denies() {
        let s = Schedule {
            timezone: "Nowhere/City".into(),
            allowed: vec![Window::parse("Mon-Sun 00:00-24:00").unwrap()],
        };
        assert!(s.validate().is_err());
        assert!(!s.permits(0));
    }
}
