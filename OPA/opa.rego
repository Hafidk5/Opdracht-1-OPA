package barmanagement

default allow := false

# Regel om een bestelling te controleren op basis van de leeftijd uit de JWT-token
allow {
    input.request.headers.Authorization  # Controleren of de Authorization-header aanwezig is
    jwt_token := split(input.request.headers.Authorization, " ")[1]  # Token uit de header halen

    # Decode de JWT-token zonder verificatie
    [_, payload, _] := io.jwt.decode(jwt_token)

    # Leeftijd uit de payload halen
    age := to_number(payload.age)  # Leeftijd omzetten naar een getal

    # Alleen Fristi toestaan voor gebruikers jonger dan 16
    age < 16
    input.request.body.DrinkName == "Fristi"
}

# Regel om een bestelling voor gebruikers van 16 jaar en ouder toe te staan
allow {
    input.request.headers.Authorization  # Controleren of de Authorization-header aanwezig is
    jwt_token := split(input.request.headers.Authorization, " ")[1]  # Token uit de header halen

    # Decode de JWT-token zonder verificatie
    [_, payload, _] := io.jwt.decode(jwt_token)

    # Leeftijd uit de payload halen
    age := to_number(payload.age)  # Leeftijd omzetten naar een getal

    # Toestaan dat alle drankjes worden besteld voor gebruikers van 16 jaar of ouder
    age >= 16
}
