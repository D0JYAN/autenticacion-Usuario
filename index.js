import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT } from './config.js'
import { UserRepository } from './user-Repository.js'
import { SECRET_JWT_KEY } from './config.js'

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())
app.use((req, res, next) => {
    const token = req.cookies.access_token

    req.session = { user: null }

    try {
        const data = jwt.verify(token, SECRET_JWT_KEY)
        req.session.user = data
    } catch (error) {}

    next()// Seguir al siguiente middleware
})

app.get('/', (req, res) => {
    const { user} = req.session
    res.render('index', user)
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body

    try {
        const user = await UserRepository.login({ username, password })
        //Crear el token
        const token = jwt.sign({ id: user._id, username: user.username }, SECRET_JWT_KEY, {
            expiresIn: '1h'// expira en 1 hora
        })
        res
        .cookie('access_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 60 * 60 * 1000 // expira en 1 hora
        })
        .send({ user, token })
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
    res
       .clearCookie('access_token')
       .json({ message: 'Sesion cerrada' })
       //Aqui tambien se puede hacer una redireccion
})

app.get('/protected', (req, res) => {
    const { user } = req.session
    if (!user) return res.status(403).send('Acceso no autorizado')
    res.render('protected', user)
})

app.listen(PORT, () => {
    console.log(`Servidor activo en  http://localhost:${PORT}`)
})
