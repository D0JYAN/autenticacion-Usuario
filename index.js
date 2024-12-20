import express from 'express'
import { PORT } from './config.js'
import { UserRepository } from './user-Repository.js'

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())

app.get('/', (req, res) => {
    res.render('index')
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body

    try {
        const user = await UserRepository.login({ username, password })
        res.send({ user })
    } catch (error) {
        res.status(401).send(error.message)
    }
})

app.post('/register', async (req, res) => {
    const { username, password } = req.body

    try {
        const id = await UserRepository.create({ username, password })
        res.send({ id })
    } catch (error) {
        res.status(404).send(error.message)
    }
})

app.post('/logout', (req, res) => {

})

app.get('/protected', (req, res) => {
    // TODO: if sesion del usuario
    res.render('protected', { username: 'jesus' })
    // TODO: else 401
})

app.listen(PORT, () => {
    console.log(`Servidor activo en  http://localhost:${PORT}`)
})
