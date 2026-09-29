/**
 * Shape rules named in spec/classes.yaml: Luhn, IIN, SSN structure, dates.
 * Pure functions; they return booleans or a brand name, never the digits.
 */
import type { BrandRule, ClassSpec, Spec } from './spec.ts';

const DIGITS = /^[0-9]+$/;

export function luhnValid(digits: string): boolean {
  if (!DIGITS.test(digits)) return false;
  let total = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
    double = !double;
  }
  return total % 10 === 0;
}

/** The brand whose IIN range and length the number falls in, or null. */
export function cardBrand(digits: string, brands: readonly BrandRule[]): string | null {
  if (!DIGITS.test(digits) || digits.length < 13 || digits.length > 19) return null;
  for (const rule of brands) {
    for (const [length, lo, hi] of rule.ranges) {
      const prefix = Number(digits.slice(0, length));
      if (prefix >= lo && prefix <= hi) return rule.lengths.has(digits.length) ? rule.brand : null;
    }
  }
  return null;
}

export function isTestCard(digits: string, card: ClassSpec): boolean {
  if (card.testNumbers.has(digits)) return true;
  const limit = card.testNumbersMaxDistinctDigits;
  return limit > 0 && new Set(digits).size <= limit;
}

/** AAA-GG-SSSS: area not 000, 666 or 900-999; group not 00; serial not 0000. */
export function ssnStructureValid(digits: string): boolean {
  if (digits.length !== 9 || !DIGITS.test(digits)) return false;
  const area = Number(digits.slice(0, 3));
  if (area === 0 || area === 666 || area >= 900) return false;
  return digits.slice(3, 5) !== '00' && digits.slice(5) !== '0000';
}

function leap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

export function validDate(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12 || day < 1) return false;
  const days = [31, leap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1]!;
}

export function plausibleBirthDate(year: number, month: number, day: number, nowYear: number) {
  return year >= 1900 && year <= nowYear && validDate(year, month, day);
}

/** A two-digit birth year: this century if not in the future, else last century. */
function twoDigitYear(yy: number, nowYear: number): number {
  const year = nowYear - (nowYear % 100) + yy;
  return year <= nowYear ? year : year - 100;
}

/** date_mmddyy (6 digits) or date_mmddyyyy (8 digits), a plausible birth date. */
export function dateDigitsShape(digits: string, nowYear: number): boolean {
  const mm = Number(digits.slice(0, 2));
  const dd = Number(digits.slice(2, 4));
  if (digits.length === 6) {
    return plausibleBirthDate(twoDigitYear(Number(digits.slice(4)), nowYear), mm, dd, nowYear);
  }
  if (digits.length === 8) return plausibleBirthDate(Number(digits.slice(4)), mm, dd, nowYear);
  return false;
}

export const ISO_DATE = /(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])/g;
export const SLASHED_DATE = /(?<![0-9])([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}|[0-9]{2})(?![0-9])/g;

/** date_iso or date_slashed (m/d/yy or m/d/yyyy), a plausible birth date. */
export function dateTokenShape(token: string, nowYear: number): boolean {
  let m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(token);
  if (m) return plausibleBirthDate(Number(m[1]), Number(m[2]), Number(m[3]), nowYear);
  m = /^([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}|[0-9]{2})$/.exec(token);
  if (m) {
    let year = Number(m[3]);
    if (m[3]!.length === 2) year = twoDigitYear(year, nowYear);
    return plausibleBirthDate(year, Number(m[1]), Number(m[2]), nowYear);
  }
  return false;
}

export function digitsInRange(cls: ClassSpec, n: number): boolean {
  const { digitsMin: lo, digitsMax: hi } = cls.shape;
  return lo !== null && hi !== null && lo <= n && n <= hi;
}

/** Lengths to try for a card: the whole run if 13-19 digits, then shorter heads. */
export function cardCandidates(digits: string): number[] {
  const n = digits.length;
  const out = n >= 13 && n <= 19 ? [n] : [];
  for (let len = Math.min(19, n - 1); len > 12; len--) out.push(len);
  return out;
}

export type ShapePass = 'full' | 'soft' | 'none';

/** How a digit run fits a class's shape. */
export function shapePass(cls: ClassSpec, digits: string, spec: Spec, nowYear: number): ShapePass {
  const rules = cls.shape.rules;
  if (cls.shape.kinds.length > 0) return dateDigitsShape(digits, nowYear) ? 'full' : 'none';
  if (cls.name === 'card' || rules.includes('luhn')) {
    let best: ShapePass = 'none';
    for (const length of cardCandidates(digits)) {
      const head = digits.slice(0, length);
      if (!luhnValid(head)) continue;
      if (rules.includes('iin_known') && cardBrand(head, spec.brands) === null) {
        // Only the whole run can be a soft pass; a head must pass in full.
        if (length === digits.length && cls.shape.softRules.includes('iin_known')) best = 'soft';
        continue;
      }
      return 'full';
    }
    return best;
  }
  if (!digitsInRange(cls, digits.length)) return 'none';
  if (rules.some((r) => r.startsWith('area_') || r.startsWith('group_') || r.startsWith('serial_'))) {
    return ssnStructureValid(digits) ? 'full' : 'none';
  }
  return 'full';
}
