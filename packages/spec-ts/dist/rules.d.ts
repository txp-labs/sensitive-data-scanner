/**
 * Shape rules named in spec/classes.yaml: Luhn, IIN, SSN and ITIN structure, dates.
 * Pure functions; they return booleans or a brand name, never the digits.
 */
import type { BrandRule, ClassSpec, Spec } from './spec.ts';
export declare function luhnValid(digits: string): boolean;
/** The brand whose IIN range and length the number falls in, or null. */
export declare function cardBrand(digits: string, brands: readonly BrandRule[]): string | null;
export declare function isTestCard(digits: string, card: ClassSpec): boolean;
/** AAA-GG-SSSS: area not 000, 666 or 900-999; group not 00; serial not 0000. */
export declare function ssnStructureValid(digits: string): boolean;
/** 9GG-GG-SSSS: area 900-999; group 50-65, 70-88, 90-92 or 94-99. */
export declare function itinStructureValid(digits: string): boolean;
export declare function validDate(year: number, month: number, day: number): boolean;
export declare function plausibleBirthDate(year: number, month: number, day: number, nowYear: number): boolean;
/** date_mmddyy (6 digits) or date_mmddyyyy (8 digits), a plausible birth date. */
export declare function dateDigitsShape(digits: string, nowYear: number): boolean;
export declare const ISO_DATE: RegExp;
export declare const SLASHED_DATE: RegExp;
/** date_iso or date_slashed (m/d/yy or m/d/yyyy), a plausible birth date. */
export declare function dateTokenShape(token: string, nowYear: number): boolean;
export declare function digitsInRange(cls: ClassSpec, n: number): boolean;
/** Lengths to try for a card: the whole run if 13-19 digits, then shorter heads. */
export declare function cardCandidates(digits: string): number[];
export type ShapePass = 'full' | 'soft' | 'none';
/** How a digit run fits a class's shape. */
export declare function shapePass(cls: ClassSpec, digits: string, spec: Spec, nowYear: number): ShapePass;
