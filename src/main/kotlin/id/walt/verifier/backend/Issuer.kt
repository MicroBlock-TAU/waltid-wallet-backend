package id.walt.verifier.backend

data class Issuer(
    var did : String,
    var attributes : Collection<Attribute>
)
