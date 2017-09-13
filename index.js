// http://www.datoteke.fu.gov.si/dpr/files/TehnicnaDokumentacijaVer1.6.pdf
const fs = require('fs');
const request = require('request');
const path = require('path');
const uuidv4 = require('uuid').v4;
const validate = require('jsonschema').validate;
const jsonwebtoken = require('jsonwebtoken');
const moment = require('moment');
const md5 = require('md5');
const forge = require('node-forge');
const hexToDecimal = require('biguint-format');
const jsrsasign = require('jsrsasign');

const url = 'https://blagajne-test.fu.gov.si:9002/v1/cash_registers';
const dtf = 'Y-MM-DD[T]HH:mm:ss[Z]';

const tlsCertFile = path.resolve(__dirname, 'test-tls.cer');
const myCertFile = path.resolve(__dirname, 'XXX-1.p12');
const passphrase = 'XXX';
const fursCertPemFile = path.resolve(__dirname, 'test-sign.pem');

// Parse pem and data from p12
let key;
const p12Der = forge.util.decode64(fs.readFileSync(myCertFile).toString('base64'));
const p12Asn1 = forge.asn1.fromDer(p12Der);
const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passphrase);
const bags = p12.getBags({bagType: forge.pki.oids.certBag});
const cert = bags[forge.pki.oids.certBag][0];

// Serial number
let serial = hexToDecimal(cert['cert']['serialNumber'], 'dec');

// Header issuer and subject
const certCNs = {
  'issuer_name': cert['cert']['issuer'],
  'subject_name': cert['cert']['subject'],
}

const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, passphrase);
let map = {};

for (let sci = 0; sci < pkcs12.safeContents.length; ++sci) {
  let safeContents = pkcs12.safeContents[sci];

  for (let sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
    let safeBag = safeContents.safeBags[sbi];
    let localKeyId = null;

    if (safeBag.attributes.localKeyId) {
      localKeyId = forge.util.bytesToHex(safeBag.attributes.localKeyId[0]);

      if (!(localKeyId in map)) {
        map[localKeyId] = {
          privateKey: null,
          certChain: [],
        };
      }
    } else {
      continue;
    }

    if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
      map[localKeyId].privateKey = safeBag.key;
    } else if (safeBag.type === forge.pki.oids.certBag) {
      map[localKeyId].certChain.push(safeBag.cert);
    }
  }
}

for (let localKeyId in map) {
  let entry = map[localKeyId];

  if (entry.privateKey) {
    let privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
    key = privateKeyP12Pem;
  }
}

let header = {
  alg: 'RS256',
  subject_name: '',
  issuer_name: '',
  serial,
}

const cnTypes = ['subject_name', 'issuer_name'];

cnTypes.forEach(t => {
  for (let i = 0; i < certCNs[t].attributes.length; i++) {
    let attributes = certCNs[t].attributes[i];

    let tName = 'name';
    if ('shortName' in attributes) tName = 'shortName';

    header[t] = header[t] + ',' + attributes[tName] + '=' + attributes['value'];
  }

  header[t] = header[t].substring(1);
});

const TaxNumber = 10489185;
const IssueDateTime = moment().format('DD.MM.Y HH:mm:ss');
const InvoiceNumber = 1;
const BusinessPremiseID = 'BPID1';
const ElectronicDeviceID = 'EDID1';
const InvoiceAmount = 1220.00;

// Generate ZOI value
let ZOI = '' + TaxNumber + IssueDateTime + InvoiceNumber + BusinessPremiseID + ElectronicDeviceID +
  InvoiceAmount;

let sig = new jsrsasign.KJUR.crypto.Signature({alg: 'SHA256withRSA'});
sig.init(key);
sig.updateString(ZOI);

ZOI = md5(sig.sign);

console.log('ZOI:', ZOI);

// Invoice/Premises data
const invoice = {
  InvoiceRequest: {
    Header: {
      MessageID: uuidv4(),
      DateTime: moment().format(dtf),
    },
    Invoice: {
      TaxNumber,
      IssueDateTime: moment().format(dtf),
      NumberingStructure: 'B',
      InvoiceIdentifier: {
        BusinessPremiseID,
        ElectronicDeviceID,
        InvoiceNumber: '145'
      },
      InvoiceAmount,
      PaymentAmount: InvoiceAmount,
      TaxesPerSeller: [{
        VAT: [{
          TaxRate: 22.00,
          TaxableAmount: 1000,
          TaxAmount: 220.00,
        }]
      }],
      OperatorTaxNumber: 42531357,
      ProtectedID: ZOI,
    }
  }
}

// Generate QR code value
let qrValue = hexToDecimal(ZOI, 'dec');
while (qrValue.length < 39) qrValue = '0' + qrValue;

qrValue = qrValue + moment(IssueDateTime, 'DD.MM.Y HH:mm:ss').format('YYMMDDHHmmss');

qrValue += TaxNumber;

let controlNum = 0;
for (let i = 0; i < qrValue.length; i++) controlNum += parseInt(qrValue[i]);
controlNum %= 10;
qrValue += controlNum;

console.log('QR:', qrValue);

const premise = {
  BusinessPremiseRequest: {
    Header: {
      MessageID: uuidv4(),
      DateTime: moment().format(dtf),
    },
    BusinessPremise: {
      TaxNumber,
      BusinessPremiseID,
      BPIdentifier: {
        RealEstateBP: {
          PropertyID: {
            CadastralNumber: 365,
            BuildingNumber: 12,
            BuildingSectionNumber: 3
          },
          Address: {
            Street: 'Tržaška cesta',
            HouseNumber: '24',
            HouseNumberAdditional: 'B',
            Community: 'Ljubljana',
            City: 'Ljubljana',
            PostalCode: '1000'
          }
        }
      },
      // ValidityDate: moment().format('Y-MM-DD'),
      ValidityDate: moment().format(dtf),
      SoftwareSupplier: [{
        TaxNumber,
      }],
    }
  }
}

let payload;
// payload = premise;
payload = invoice;

// Validate payload
let schema = path.resolve(__dirname, 'FiscalVerificationSchema.json');
schema = JSON.parse(fs.readFileSync(schema));
const validation = validate(payload, schema);

if (!!validation.errors && validation.errors.length) {
  console.log(validation.errors);
  process.exit();
}

// Generate JWT
let token = jsonwebtoken.sign(payload, key, {header, algorithm: 'RS256', noTimestamp: true});

let body = {
  // EchoRequest: 'furs',
  token,
};

// request.post(url + '/echo', {
request.post(url + '/invoices', {
// request.post(url + '/invoices/register', {
  body,
  ca: fs.readFileSync(tlsCertFile),
  pfx: fs.readFileSync(myCertFile),
  passphrase, // env
  headers: {
    'content-type': 'application/json; UTF-8',
  },
  json: true,
}, function(err, res) {
  if (err) console.log(err);
  // console.log(res.body);
  const response = jsonwebtoken.verify(res.body.token,
    fs.readFileSync(fursCertPemFile), {algorithms: ['RS256']});

  if (!!payload.InvoiceRequest) {
    const eor = response.InvoiceResponse.UniqueInvoiceID;
    console.log('EOR:', eor);
    // Show EOR, ZOI, QR code on document
    if (!eor) {
      // TODO: Error (on recipient server)
    }
  }
});
