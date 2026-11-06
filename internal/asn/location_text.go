package asn

import "strings"

// LocationText produces the report value, without query diagnostics. IPinfo
// takes precedence; missing fields may be filled by a compatible source.
func LocationText(locations []Location) string {
	var ordered []Location
	for _, l := range locations {
		if l.Source == "ipinfo" {
			ordered = append(ordered, l)
		}
	}
	for _, l := range locations {
		if l.Source != "ipinfo" {
			ordered = append(ordered, l)
		}
	}
	var base Location
	found := false
	var notes []string
	for _, l := range ordered {
		if l.Status != StatusOK || locationLabel(l) == "" {
			continue
		}
		if !found {
			base = l
			found = true
			if l.Source != "ipinfo" {
				notes = append(notes, "由 "+sourceLabel(l.Source)+" 补充")
			}
			continue
		}
		countryConflict := base.CountryCode != "" && l.CountryCode != "" && !strings.EqualFold(base.CountryCode, l.CountryCode)
		regionConflict := base.Region != "" && l.Region != "" && !strings.EqualFold(base.Region, l.Region)
		cityConflict := base.City != "" && l.City != "" && !strings.EqualFold(base.City, l.City)
		if countryConflict || regionConflict || cityConflict {
			notes = append(notes, "其他可能："+locationLabel(l)+"，"+sourceLabel(l.Source))
			continue // never fill a city from a conflicting country/region
		}
		var filled []string
		if base.CountryCode == "" && base.Country == "" && (l.CountryCode != "" || l.Country != "") {
			base.CountryCode, base.Country = l.CountryCode, l.Country
			filled = append(filled, "国家/地区")
		}
		if base.Region == "" && l.Region != "" {
			base.Region = l.Region
			filled = append(filled, "地区")
		}
		if base.City == "" && l.City != "" {
			base.City = l.City
			filled = append(filled, "城市")
		}
		if len(filled) > 0 {
			notes = append(notes, strings.Join(filled, "、")+"由 "+sourceLabel(l.Source)+" 补充")
		}
	}
	if !found {
		return "未知"
	}
	value := locationLabel(base)
	if len(notes) > 0 {
		value += "（" + strings.Join(notes, "；") + "）"
	}
	return value
}
func locationLabel(l Location) string {
	country := l.CountryCode
	if country == "" {
		country = l.Country
	}
	var parts []string
	for _, s := range []string{country, l.Region, l.City} {
		if s != "" && (len(parts) == 0 || !strings.EqualFold(parts[len(parts)-1], s)) {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " / ")
}
func sourceLabel(s string) string {
	switch s {
	case "ipinfo":
		return "IPinfo"
	case "geojs":
		return "GeoJS"
	}
	return s
}
