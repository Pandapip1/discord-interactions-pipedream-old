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
  async run(event) {
    const signature = event.headers['X-Signature-Ed25519'];
    const timestamp = event.headers['X-Signature-Timestamp'];
    const body = JSON.stringify(event.body);

    const isVerified = nacl.sign.detached.verify(
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
    this.$emit(event.body, {
      id: signature,
      ts: timestamp
    });
  }
};
