const DIGITS = /^[0-9]+$/;
export function luhnValid(digits) {
    if (!DIGITS.test(digits))
        return false;
    let total = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (double) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        total += d;
        double = !double;
    }
    return total % 10 === 0;
}
/** The brand whose IIN range and length the number falls in, or null. */
export function cardBrand(digits, brands) {
    if (!DIGITS.test(digits) || digits.length < 13 || digits.length > 19)
        return null;
    for (const rule of brands) {
        for (const [length, lo, hi] of rule.ranges) {
            const prefix = Number(digits.slice(0, length));
            if (prefix >= lo && prefix <= hi)
                return rule.lengths.has(digits.length) ? rule.brand : null;
        }
    }
    return null;
}
export function isTestCard(digits, card) {
    if (card.testNumbers.has(digits))
        return true;
    const limit = card.testNumbersMaxDistinctDigits;
    return limit > 0 && new Set(digits).size <= limit;
}
/** AAA-GG-SSSS: area not 000, 666 or 900-999; group not 00; serial not 0000. */
export function ssnStructureValid(digits) {
    if (digits.length !== 9 || !DIGITS.test(digits))
        return false;
    const area = Number(digits.slice(0, 3));
    if (area === 0 || area === 666 || area >= 900)
        return false;
    return digits.slice(3, 5) !== '00' && digits.slice(5) !== '0000';
}
/** ITIN groups: 50-65, 70-88, 90-92 and 94-99. */
const ITIN_GROUPS = [
    [50, 65],
    [70, 88],
    [90, 92],
    [94, 99],
];
/** 9GG-GG-SSSS: area 900-999; group 50-65, 70-88, 90-92 or 94-99. */
export function itinStructureValid(digits) {
    if (digits.length !== 9 || !DIGITS.test(digits) || digits[0] !== '9')
        return false;
    const group = Number(digits.slice(3, 5));
    return ITIN_GROUPS.some(([lo, hi]) => group >= lo && group <= hi);
}
const SSN_RULES = ['area_not_000_666_9xx', 'group_not_00', 'serial_not_0000'];
const ITIN_RULES = ['area_9xx', 'group_50_65_70_88_90_92_94_99'];
function leap(year) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
export function validDate(year, month, day) {
    if (month < 1 || month > 12 || day < 1)
        return false;
    const days = [31, leap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return day <= days[month - 1];
}
export function plausibleBirthDate(year, month, day, nowYear) {
    return year >= 1900 && year <= nowYear && validDate(year, month, day);
}
/** A two-digit birth year: this century if not in the future, else last century. */
function twoDigitYear(yy, nowYear) {
    const year = nowYear - (nowYear % 100) + yy;
    return year <= nowYear ? year : year - 100;
}
/** date_mmddyy (6 digits) or date_mmddyyyy (8 digits), a plausible birth date. */
export function dateDigitsShape(digits, nowYear) {
    const mm = Number(digits.slice(0, 2));
    const dd = Number(digits.slice(2, 4));
    if (digits.length === 6) {
        return plausibleBirthDate(twoDigitYear(Number(digits.slice(4)), nowYear), mm, dd, nowYear);
    }
    if (digits.length === 8)
        return plausibleBirthDate(Number(digits.slice(4)), mm, dd, nowYear);
    return false;
}
export const ISO_DATE = /(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])/g;
export const SLASHED_DATE = /(?<![0-9])([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}|[0-9]{2})(?![0-9])/g;
/** date_iso or date_slashed (m/d/yy or m/d/yyyy), a plausible birth date. */
export function dateTokenShape(token, nowYear) {
    let m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(token);
    if (m)
        return plausibleBirthDate(Number(m[1]), Number(m[2]), Number(m[3]), nowYear);
    m = /^([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}|[0-9]{2})$/.exec(token);
    if (m) {
        let year = Number(m[3]);
        if (m[3].length === 2)
            year = twoDigitYear(year, nowYear);
        return plausibleBirthDate(year, Number(m[1]), Number(m[2]), nowYear);
    }
    return false;
}
export function digitsInRange(cls, n) {
    const { digitsMin: lo, digitsMax: hi } = cls.shape;
    return lo !== null && hi !== null && lo <= n && n <= hi;
}
/** Lengths to try for a card: the whole run if 13-19 digits, then shorter heads. */
export function cardCandidates(digits) {
    const n = digits.length;
    const out = n >= 13 && n <= 19 ? [n] : [];
    for (let len = Math.min(19, n - 1); len > 12; len--)
        out.push(len);
    return out;
}
/** How a digit run fits a class's shape. */
export function shapePass(cls, digits, spec, nowYear) {
    const rules = cls.shape.rules;
    if (cls.shape.kinds.length > 0)
        return dateDigitsShape(digits, nowYear) ? 'full' : 'none';
    if (cls.name === 'card' || rules.includes('luhn')) {
        let best = 'none';
        for (const length of cardCandidates(digits)) {
            const head = digits.slice(0, length);
            if (!luhnValid(head))
                continue;
            if (rules.includes('iin_known') && cardBrand(head, spec.brands) === null) {
                // Only the whole run can be a soft pass; a head must pass in full.
                if (length === digits.length && cls.shape.softRules.includes('iin_known'))
                    best = 'soft';
                continue;
            }
            return 'full';
        }
        return best;
    }
    if (!digitsInRange(cls, digits.length))
        return 'none';
    if (rules.some((r) => ITIN_RULES.includes(r)))
        return itinStructureValid(digits) ? 'full' : 'none';
    if (rules.some((r) => SSN_RULES.includes(r)))
        return ssnStructureValid(digits) ? 'full' : 'none';
    return 'full';
}
