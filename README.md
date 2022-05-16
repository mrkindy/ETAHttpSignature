# Egyptian Tax EInvoice HttpSignature
Sign tax payers documents before sending the documents to Egyptian Tax Authority.
so you can integrate with any other application (Desktop Or Web)

## How to use
- Download [ETAHttpSignature.zip](https://github.com/mrkindy/ETAHttpSignature/raw/master/ETAHttpSignature.zip)
- Extract ETAHttpSignature.zip files in safe folder
- Run HttpSignature.exe
- Now you can sign your [invoice serialize data](https://sdk.invoicing.eta.gov.eg/document-serialization-approach/) by sending it to `ws://localhost:18088` by WebSocket

## Features
- Sign Egyptian Tax EInvoice through Websocket

## Documentation

Send the following json as `text` to `ws://localhost:18088`

```
{Document:'{serialize_data}',TokenCertificate:'Egypt Trust Sealing CA'}
```
And you will receive the json as `text` and you should convert it to json

```
{cades:"{Data}"}
```
{Data} could be :
- NO_SOLTS_FOUND
- PASSWORD_INVAILD
- CERTIFICATE_NOT_FOUND
- NO_DEVICE_DETECTED
- Or Signature as a long text

## Javascript Example

``` javascript
var signature;
var socket = new WebSocket("ws://localhost:18088");

function ConnectToSignatureServer() {
    socket.send('{Document:\'{serialize_data}\',TokenCertificate:\'Egypt Trust Sealing CA\'}');
    
    socket.onmessage = function (response) { 
        var responseObj = JSON.parse(response.data);

        if(responseObj.cades != 'NO_SOLTS_FOUND' && responseObj.cades != 'PASSWORD_INVAILD' && responseObj.cades != 'CERTIFICATE_NOT_FOUND' && responseObj.cades != 'NO_DEVICE_DETECTED')
        {
            alert('Document Signed');
            signature = responseObj.cades;
        }else{
            alert(responseObj.cades);
        }
    };
}

socket.onclose = function() { 
    alert('Connection is closed');
};

socket.onerror = function() { 
    alert('Connection Error');
};
socket.onopen = function() { 
    alert('Connection Open');
};
```

## Contribution
Your contribution is welcome

## License
The MIT License (MIT). Please see [License File](LICENSE) for more information.

## Credit
[Ibrahim Abotaleb](https://github.com/mrkindy)

[EInvoicingSigner](https://github.com/bassemAgmi/EInvoicingSigner)