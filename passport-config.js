const { authenticate } = require('passport')

const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport) {
    const authenticateUser = (email, passord, done) => { 
        const user = getUserByEmail(email)
        if(user  == null) {
            return done(null, false, {message: 'Não existe utilizador com esse email'})
        }
    }

    passport.use(new localStrategy({ usernameField: 'email'})
    , authenticateUser) 
    passport.serializaUser((user, done) => {})
    passport.deserializaUser((id, done) => {})
}