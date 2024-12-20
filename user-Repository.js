import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUND } from './config.js'
const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }
})

export class UserRepository {
    static create ({ username, password }) {
        // Validaciones de username
        if (typeof username !== 'string') throw new Error('El usuario debe ser un texto')
        if (username.length < 3) throw new Error('El nombre de usuario debe tener al menos 3 caracteres')

        // Validaciones de password
        if (typeof password !== 'string') throw new Error('La contraseña debe ser un texto')
        if (password.length < 8) throw new Error('La contraseña debe tener al menos 8 caracteres')

        // Asegurar que el username no existe
        const user = User.findOne({ username })
        if (user) throw new Error('El nombre de usuario ya existe')

        const id = crypto.randomUUID()
        const hashedPassword = bcrypt.hashSync(password, SALT_ROUND)

        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()

        return id
    }
    static login ({ username, password }) {}
}
