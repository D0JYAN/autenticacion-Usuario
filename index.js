import express from 'express'
import { PORT } from './config.js'
import { UserRepository } from './user-Repository.js'

const app = express()
app.use(express.json())

app.get('/', (req, res) => {
    res.send('Hello, World')
})

app.post('/login', (req, res) => {

})

app.post('/register', (req, res) => {
    const { username, password } = req.body

    try {
        const id = UserRepository.create({ username, password })
        res.send({ id })
    } catch (error) {
        res.status(404).send(error.message)
    }
})

app.post('/logout', (req, res) => {

})

app.get('/protected', (req, res) => {

})

app.listen(PORT, () => {
    console.log(`Servidor activo en  http://localhost:${PORT}`)
})
