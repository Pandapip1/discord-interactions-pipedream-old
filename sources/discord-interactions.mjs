import nacl from "tweetnacl";

export default {
  name: "discord-interactions",
  version: "0.0.1",
  props: {
    http: {
      type: "$.interface.http",
      customResponse: true
    },
    pubKey: {
      type: "string",
      label: "Public Key",
      secret: true
    }
  },
  methods: {
    async respond(data) {
      return await this.http.respond({
        status: 200,
        body: data,
        headers: {
          "content-type": "application/json",
        },
      });
    }
  },
  async run(event) {
    function getParameterCaseInsensitive(object, key) {
      return object[Object.keys(object)
        .find(k => k.toLowerCase() === key.toLowerCase())
      ];
    }
    const signature = getParameterCaseInsensitive(event.headers, 'X-Signature-Ed25519');
    const timestamp = getParameterCaseInsensitive(event.headers, 'X-Signature-Timestamp');
    const body = event.bodyRaw;

    const isVerified = signature && timestamp && body && nacl.sign.detached.verify(
      Buffer.from(timestamp + body),
      Buffer.from(signature, 'hex'),
      Buffer.from(this.pubKey, 'hex')
    );

    if (!isVerified) {
      return await this.http.respond({
        status: 401,
        body: {
          msg: "invalid request signature"
        },
        headers: {
          "content-type": "application/json",
        },
      });
    }
    if (event.body.type == 1){
      return await this.http.respond({
        status: 200,
        body: {
          type: 1
        },
        headers: {
          "content-type": "application/json",
        },
      });
    }
    
    const emittedEvent = event.body;
    emittedEvent.respond = this.respond;
    
    return this.$emit(emittedEvent, {
      id: signature,
      ts: timestamp
    });
  }
};
