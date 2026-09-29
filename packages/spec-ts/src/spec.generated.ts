// Generated from spec/classes.yaml and spec/normalize.yaml by scripts/gen-spec.ts.
// Do not edit by hand: change the YAML and run `npm run gen:spec`.

export const CLASSES_RAW: unknown = {
  "specVersion": "0.1",
  "classes": {
    "us_ssn": {
      "severity": "high",
      "promptPhrases": [
        "social security number",
        "\\bssn\\b"
      ],
      "shape": {
        "digits": 9,
        "rules": [
          "area_not_000_666_9xx",
          "group_not_00",
          "serial_not_0000"
        ]
      },
      "standalone": "formatted",
      "contextWords": [
        "social",
        "ssn",
        "social security"
      ],
      "contextExclusions": [
        "last (?:four|4)(?: digits)?(?: of)?(?: (?:your|the|my))? (?:social(?: security)?(?: number)?|ssn)"
      ],
      "dummyValues": [
        "078051120",
        "219099999",
        "123456789",
        "111111111",
        "987654320"
      ]
    },
    "card": {
      "severity": "high",
      "promptPhrases": [
        "credit card number",
        "card number",
        "debit card"
      ],
      "shape": {
        "digits": [
          13,
          19
        ],
        "rules": [
          "luhn",
          "iin_known"
        ],
        "softRules": [
          "iin_known"
        ]
      },
      "promptedWithoutShape": "flag_low_confidence",
      "standalone": "any",
      "contextWords": [
        "card",
        "cards",
        "credit",
        "debit",
        "visa",
        "mastercard",
        "master card",
        "amex",
        "american express",
        "discover",
        "jcb",
        "diners",
        "unionpay",
        "union pay",
        "maestro",
        "cardholder",
        "exp",
        "expiry",
        "expiration",
        "expires",
        "cvv",
        "cvc",
        "payment",
        "billing"
      ],
      "suppressWords": [
        "order",
        "invoice",
        "tracking",
        "phone",
        "telephone",
        "mobile",
        "fax",
        "imei",
        "iccid",
        "isbn",
        "serial",
        "uuid",
        "guid",
        "trace",
        "request id",
        "transaction id",
        "txn",
        "confirmation",
        "reference",
        "ref",
        "account id",
        "customer id",
        "timestamp",
        "epoch"
      ],
      "excludeKnownTestNumbers": true,
      "testNumbers": [
        "4111111111111111",
        "4012888888881881",
        "4222222222222",
        "4242424242424242",
        "4000056655665556",
        "4000000000000002",
        "4000000000009995",
        "5555555555554444",
        "5105105105105100",
        "5200828282828210",
        "2223003122003222",
        "2223000048400011",
        "378282246310005",
        "371449635398431",
        "378734493671000",
        "6011111111111117",
        "6011000990139424",
        "6011981111111113",
        "3530111333300000",
        "3566002020360505",
        "30569309025904",
        "38520000023237",
        "36227206271667",
        "6200000000000005",
        "6759649826438453"
      ],
      "testNumbersMaxDistinctDigits": 2
    },
    "dob": {
      "severity": "medium",
      "promptPhrases": [
        "date of birth",
        "\\bdob\\b",
        "birthday",
        "born"
      ],
      "shape": {
        "kinds": [
          "date_mmddyy",
          "date_mmddyyyy",
          "date_slashed",
          "date_iso",
          "spoken_date"
        ]
      },
      "standalone": "never",
      "contextWords": [
        "date of birth",
        "dob",
        "d.o.b",
        "born",
        "birth date",
        "birthdate",
        "birthday"
      ]
    },
    "cvv": {
      "severity": "high",
      "promptPhrases": [
        "security code",
        "\\bcvv\\b",
        "three digit code"
      ],
      "shape": {
        "digits": [
          3,
          4
        ]
      }
    },
    "pin": {
      "severity": "high",
      "promptPhrases": [
        "\\bpin\\b"
      ],
      "shape": {
        "digits": [
          4,
          6
        ]
      }
    },
    "account_number": {
      "severity": "medium",
      "promptPhrases": [
        "account number"
      ],
      "shape": {
        "digits": [
          6,
          17
        ]
      }
    },
    "us_ssn_last4": {
      "severity": "low",
      "promptPhrases": [
        "last four of your social",
        "last 4 of your ssn"
      ],
      "shape": {
        "digits": 4
      }
    }
  },
  "retryPrefixes": [
    "sorry. i didn't get that",
    "i'm sorry, i didn't catch that"
  ],
  "promptCarryover": {
    "turns": 1,
    "surviveRetry": true
  },
  "contextWindow": {
    "turnsBefore": 2
  },
  "cardBrands": [
    {
      "brand": "discover",
      "prefixes": [
        "622126-622925"
      ],
      "lengths": [
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "maestro",
      "prefixes": [
        "5018",
        "5020",
        "5038",
        "5893",
        "6304",
        "6759",
        "6761-6763"
      ],
      "lengths": [
        13,
        14,
        15,
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "mir",
      "prefixes": [
        "2200-2204"
      ],
      "lengths": [
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "visa",
      "prefixes": [
        "4"
      ],
      "lengths": [
        13,
        16,
        19
      ]
    },
    {
      "brand": "mastercard",
      "prefixes": [
        "51-55",
        "2221-2720"
      ],
      "lengths": [
        16
      ]
    },
    {
      "brand": "amex",
      "prefixes": [
        "34",
        "37"
      ],
      "lengths": [
        15
      ]
    },
    {
      "brand": "discover",
      "prefixes": [
        "6011",
        "644-649",
        "65"
      ],
      "lengths": [
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "jcb",
      "prefixes": [
        "3528-3589"
      ],
      "lengths": [
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "diners",
      "prefixes": [
        "300-305",
        "36",
        "38-39"
      ],
      "lengths": [
        14,
        15,
        16,
        17,
        18,
        19
      ]
    },
    {
      "brand": "unionpay",
      "prefixes": [
        "62"
      ],
      "lengths": [
        16,
        17,
        18,
        19
      ]
    }
  ]
};

export const NORMALIZE_RAW: unknown = {
  "specVersion": "0.1",
  "steps": [
    {
      "strip_keypad_terminator": [
        "#",
        "*"
      ]
    },
    {
      "spoken_dates_to_iso": {
        "months": {
          "january": 1,
          "jan": 1,
          "february": 2,
          "feb": 2,
          "march": 3,
          "mar": 3,
          "april": 4,
          "apr": 4,
          "may": 5,
          "june": 6,
          "jun": 6,
          "july": 7,
          "jul": 7,
          "august": 8,
          "aug": 8,
          "september": 9,
          "sept": 9,
          "sep": 9,
          "october": 10,
          "oct": 10,
          "november": 11,
          "nov": 11,
          "december": 12,
          "dec": 12
        },
        "ordinals": {
          "first": 1,
          "second": 2,
          "third": 3,
          "fourth": 4,
          "fifth": 5,
          "sixth": 6,
          "seventh": 7,
          "eighth": 8,
          "ninth": 9,
          "tenth": 10,
          "eleventh": 11,
          "twelfth": 12,
          "thirteenth": 13,
          "fourteenth": 14,
          "fifteenth": 15,
          "sixteenth": 16,
          "seventeenth": 17,
          "eighteenth": 18,
          "nineteenth": 19,
          "twentieth": 20,
          "thirtieth": 30
        },
        "units": {
          "one": 1,
          "two": 2,
          "three": 3,
          "four": 4,
          "five": 5,
          "six": 6,
          "seven": 7,
          "eight": 8,
          "nine": 9
        },
        "teens": {
          "ten": 10,
          "eleven": 11,
          "twelve": 12,
          "thirteen": 13,
          "fourteen": 14,
          "fifteen": 15,
          "sixteen": 16,
          "seventeen": 17,
          "eighteen": 18,
          "nineteen": 19
        },
        "tens": {
          "twenty": 20,
          "thirty": 30,
          "forty": 40,
          "fifty": 50,
          "sixty": 60,
          "seventy": 70,
          "eighty": 80,
          "ninety": 90
        },
        "yearRange": [
          1900,
          2099
        ]
      }
    },
    {
      "number_words_to_digits": {
        "words": {
          "zero": 0,
          "oh": 0,
          "o": 0,
          "one": 1,
          "two": 2,
          "three": 3,
          "four": 4,
          "five": 5,
          "six": 6,
          "seven": 7,
          "eight": 8,
          "nine": 9
        },
        "zeroOnlyNextToDigits": [
          "oh",
          "o"
        ],
        "multipliers": {
          "double": 2,
          "triple": 3
        }
      }
    },
    {
      "drop_fillers_between_digits": [
        "uh",
        "um",
        "umm",
        "er",
        "erm",
        "ah",
        "hmm",
        "mm"
      ]
    },
    {
      "collapse_digit_separators": [
        " ",
        "-",
        ".",
        ","
      ]
    },
    {
      "join_same_speaker_turns": {
        "withinSeconds": 15,
        "stopWhenClassComplete": true,
        "maxInterveningTurns": 3,
        "neverJoinChannels": [
          "dtmf"
        ]
      }
    }
  ]
};
