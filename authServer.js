require("dotenv").config()
const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")

app.use(express.json())

let refreshTokens = []

app.delete("/logout", (req, res) => {
    refreshTokens = []
    res.sendStatus(204)
})

app.post("/token", (req, res) => {
    const x = req.body.token
    if(x == null) return res.sendStatus(401)
    if(!refreshTokens.includes(x)) return res.sendStatus(403)

    jwt.verify(x, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accesToken = generateAccesToken({name: user.name})
        res.json({accesToken: accesToken})
    })
})

app.post("/login", (req, res) => {
    const username = req.body.username
    const user = {name: username}

    const accesToken = generateAccesToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    res.json({accesToken: accesToken, refreshToken: refreshToken})
})

function generateAccesToken(user) {
    return jwt.sign(user, process.env.ACCES_TOKEN_SECRET, {expiresIn: "15s"})
}

app.listen(4000, console.log("Running on 4000"))