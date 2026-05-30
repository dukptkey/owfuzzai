{
  "beacon": {
    "subtype": 8,
    "fixed": "00000000000000000000000000000000",
    "ies": [
      {
        "id": 0,
        "name": "SSID",
        "presence": "mandatory",
        "value": ""
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": "82"
      },
      {
        "id": 3,
        "name": "DS Parameter Set",
        "presence": "optional",
        "value": "01"
      },
      {
        "id": 5,
        "name": "TIM",
        "presence": "optional",
        "value": ""
      },
      {
        "id": 7,
        "name": "Country",
        "presence": "optional",
        "value": ""
      },
      {
        "id": 48,
        "name": "RSN",
        "presence": "optional",
        "value": ""
      },
      {
        "id": 50,
        "name": "Extended Supported Rates",
        "presence": "optional",
        "value": ""
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
        "value": ""
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": ""
      },
      {
        "id": 50,
        "name": "Extended Supported Rates",
        "presence": "optional",
        "value": ""
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
        "value": ""
      }
    ]
  },
  "assoc_request": {
    "subtype": 0,
    "fixed": "00000000",
    "ies": [
      {
        "id": 0,
        "name": "SSID",
        "presence": "mandatory",
        "value": ""
      },
      {
        "id": 1,
        "name": "Supported Rates",
        "presence": "mandatory",
        "value": "82"
      },
      {
        "id": 48,
        "name": "RSN",
        "presence": "conditional",
        "value": ""
      },
      {
        "id": 127,
        "name": "Extended Capabilities",
        "presence": "optional",
        "value": ""
      }
    ]
  }
}