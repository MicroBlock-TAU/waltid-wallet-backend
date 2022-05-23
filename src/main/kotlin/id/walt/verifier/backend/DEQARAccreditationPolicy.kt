package id.walt.verifier.backend

//import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.*
import com.beust.klaxon.Klaxon
import id.walt.auditor.VerificationPolicy
import id.walt.model.TrustedIssuer
import id.walt.services.WaltIdServices
import id.walt.services.essif.TrustedIssuerClient
import id.walt.vclib.credentials.VerifiablePresentation
import id.walt.vclib.model.VerifiableCredential
import io.ktor.client.request.*
import io.ktor.http.*
import java.util.*


class DEQARAccreditationPolicy: VerificationPolicy() {
    val eqarDid = "did:ebsi:zk4bhCepWSYp9RhZkRPiwUL"

    override val description: String
        get() = "Check the TIR record."

    override fun doVerify(vc: VerifiableCredential): Boolean {
        if ( vc is VerifiablePresentation) {
            vc.verifiableCredential.forEach {
                if (!verifyVc(it)) {
                    return false
                }
            }

            return true
        }

        return verifyVc( vc )
    }

    private fun verifyVc( vc: VerifiableCredential ): Boolean = runBlocking {
        val decoder: Base64.Decoder = Base64.getDecoder()
        val did = vc.issuer
        var eqarAcreditation = false
        val tirRecord = runCatching {
                val trustedIssuer: String =
                    WaltIdServices.http.get("https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers/$did")
                Klaxon().parse<Issuer>(trustedIssuer)!!

        }.getOrElse { return@runBlocking false }

        tirRecord.attributes.forEach {
            val attribute = String(decoder.decode(it.body))
            if (attribute.contains("https://www.w3.org/2018/credentials/v1", true)) {
                val issuerAttestationInfo = Klaxon().parse<DeqarAttestation>(attribute)
                if ( issuerAttestationInfo?.issuer.equals(eqarDid) ) {
                    eqarAcreditation = true
                }
            }
        }
        return@runBlocking eqarAcreditation
    }
}