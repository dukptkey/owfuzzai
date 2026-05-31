{
  "beacon": {
    "subtype": 8,
    "fixed": "000000000000000064000100",
    "ies": [
      {
        "id": 0,
        "name": "SSID",
        "presence": "mandatory",
        "value": "6f7766757a7a6169"
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": "82848b960c121824"
      },
      {
        "id": 3,
        "name": "DS Parameter Set",
        "presence": "optional",
        "value": "06"
      },
      {
        "id": 5,
        "name": "TIM",
        "presence": "optional",
        "value": "00010000"
      },
      {
        "id": 7,
        "name": "Country",
        "presence": "optional",
        "value": "555320010b1e"
      },
      {
        "id": 48,
        "name": "RSN",
        "presence": "optional",
        "value": "0100000fac040100000fac040100000fac020000"
      },
      {
        "id": 50,
        "name": "Extended Supported Rates",
        "presence": "optional",
        "value": "3048606c"
      }
    ]
  },
  "probe_request": {
    "subtype": 4,
    "fixed": "",
    "ies": [
      {
        "id": 0,
        "name": "SSID",
        "presence": "mandatory",
        "value": "6f7766757a7a6169"
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": "82848b960c121824"
      },
      {
        "id": 50,
        "name": "Extended Supported Rates",
        "presence": "optional",
        "value": "3048606c"
      }
    ]
  },
  "authentication": {
    "subtype": 11,
    "fixed": "000001000000",
    "ies": [
      {
        "id": 16,
        "name": "Challenge Text",
        "presence": "conditional",
        "value": "f1e2d3c4b5a697887766554433221100"
      }
    ]
  },
  "assoc_request": {
    "subtype": 0,
    "fixed": "11040a00",
    "ies": [
      {
        "id": 0,
        "name": "SSID",
        "presence": "mandatory",
        "value": "6f7766757a7a6169"
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": "82848b960c121824"
      },
      {
        "id": 48,
        "name": "RSN",
        "presence": "conditional",
        "value": "0100000fac040100000fac040100000fac020000"
      },
      {
        "id": 127,
        "name": "Extended Capabilities",
        "presence": "optional",
        "value": "0000000000000040"
      }
    ]
  }
}