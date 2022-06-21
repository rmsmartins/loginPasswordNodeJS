const { authenticate } = require('passport')

const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail) {
    const authenticateUser = (email, passord, done) => { 
        const user = getUserByEmail(email)
        if(user  == null) {
            return done(null, false, {message: 'Não existe utilizador com esse email'})
        }

        try{
            if (await bcrypt.compare(password, user.passord)) {
                return done(null, user)
            } else {
                return done(null, false, { message: 'Password incorreta' })
            }
        } catch {
            return done(e)
        }
    }

    passport.use(new localStrategy({ usernameField: 'email'})
    , authenticateUser) 
    passport.serializaUser((user, done) => {})
    passport.deserializaUser((id, done) => {})
}

modules.exports = initialize 