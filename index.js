/**
 * Class to handle 
 */
class EZWebAuthn{
	
    //
    // SIMPLE STRING-TO-buffer`
    //
    #utf8StringToBuffer = (value) => {
        return new TextEncoder().encode(value);
    }

    //
    // SIMPLE buffer-TO-STRING
    // 
    //
    #bufferToUTF8String = (value) =>  {
        return new TextDecoder('utf-8').decode(value);
    }

    //
    // ARRAYBUFFER ====> Base64
    //
    #bufferToBase64URLString = (buffer) => {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const charCode of bytes) {
            str += String.fromCharCode(charCode);
        }
        const base64String = btoa(str);
        return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    //
    // Base64 =====> ARRAYBUFFER
    //
    #base64URLStringToBuffer = (base64URLString) => {
        
        const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (base64.length % 4)) % 4;
        const padded = base64.padEnd(base64.length + padLength, '=');
        const binary = atob(padded);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    //
    // CHECK TO SEE IF THE BROWSWER SUPPORTS WEB-AUTHN
    //
    #browserSupportsWebauthn = () => {
        return ((window === null || window === void 0 ? void 0 : window.PublicKeyCredential) !== undefined && typeof window.PublicKeyCredential === 'function');
    }


    //
    // ?????????????????????
    // Convert the ID of a descriptor to base64; but retain the rest?
    //
    #toPublicKeyCredentialDescriptor = (descriptor) => {
        
        var that = this;
        
        const { id } = descriptor;
        return {
            ...descriptor,
            id: that.base64URLStringToBuffer(id),
        };
    }


    // THROW THIS AWAY ASAP!!!
	priv = {}


    //
    // ======================================================
    // ======================================================
    // ======================================================
    // ======================================================
    //
    //
    async startRegistration(creationOptionsJSON) {

        var that = this;
        
        if (!that.#browserSupportsWebauthn()) {
            throw new Error('WebAuthn is not supported in this browser');
        }

        //
        // This builds out the options that `window.navigator` can consume
        // based on what options we feed it
        //
        const publicKey = {
            ...creationOptionsJSON,
            challenge: that.#base64URLStringToBuffer(creationOptionsJSON.challenge),
            user: {
                ...creationOptionsJSON.user,
                id: this.#utf8StringToBuffer(creationOptionsJSON.user.id),
            }
        };
        

        //
        // Push our options into navigator and hope that a valid credential comes out
        // the other side
        //
        const credential = (await navigator.credentials.create({ publicKey: publicKey }));

        if (!credential) {
            throw new Error('Registration was not completed');
        }

        //
        // Pull the core constituents out of the credential
        // that the navigator provided us
        //
        const { id, rawId, response, type } = credential;

        //
        // Create an "authenticator" object that we can use later
        // with binary arrays stored in base64
        //
        const credentialJSON = {
            id,
            rawId: that.#bufferToBase64URLString(rawId),
            response: {
                attestationObject: that.#bufferToBase64URLString(response.attestationObject),
                clientDataJSON: that.#bufferToBase64URLString(response.clientDataJSON),
            },
            type,
            clientExtensionResults: credential.getClientExtensionResults(),
        };

        if (typeof response.getTransports === 'function') {
            credentialJSON.transports = response.getTransports();
        }

        return credentialJSON;
    }


    //
    // ======================================================
    // ======================================================
    // ======================================================
    // ======================================================
    //
    //
    async startAuthentication(requestOptionsJSON) {
        var that = this;
        
        var _a, _b;
        if (!that.#browserSupportsWebauthn()) {
            throw new Error('WebAuthn is not supported in this browser');
        }
        
        let allowCredentials;
        if (((_a = requestOptionsJSON.allowCredentials) === null || _a === void 0 ? void 0 : _a.length) !== 0) {
            allowCredentials = (_b = requestOptionsJSON.allowCredentials) === null || _b === void 0 ? void 0 : _b.map((x) => {return this.#toPublicKeyCredentialDescriptor(x)});
        }
        const publicKey = {
            ...requestOptionsJSON,
            challenge: that.#base64URLStringToBuffer(requestOptionsJSON.challenge),
            allowCredentials,
        };

        const credential = (await navigator.credentials.get({ publicKey }));
        if (!credential) {
            throw new Error('Authentication was not completed');
        }
        const { id, rawId, response, type } = credential;
        let userHandle = undefined;
    
        if (response.userHandle) {
            userHandle = that.#bufferToUTF8String(response.userHandle);
        }
        return {
            id,
            rawId: that.#bufferToBase64URLString(rawId),
            response: {
                authenticatorData: that.#bufferToBase64URLString(response.authenticatorData),
                clientDataJSON: that.#bufferToBase64URLString(response.clientDataJSON),
                signature: that.#bufferToBase64URLString(response.signature),
                userHandle,
            },
            type,
            clientExtensionResults: credential.getClientExtensionResults(),
        };
    }
    
    //
    // ======================================================
    // ======================================================
    // ======================================================
    // ======================================================
    //
    //
    async platformAuthenticatorIsAvailable() {
        if (!browserSupportsWebauthn()) {
            return false;
        }
        return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }

}