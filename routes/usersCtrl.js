// Imports
const bcrypt = require('bcrypt');
const jwtUtils = require('../utils/jwt.utils');
const models = require('../models');

// Routes
module.exports = {
    register: function(req, res) {

        // Params
        var lastName = req.body.lastName;
        var firstName = req.body.firstName;
        var email = req.body.email;
        var password = req.body.password;
        var role = req.body.role;

        if (lastName == null || firstName == null || email == null || password == null || role == null) { 
            return res.status(400).json({ 'error': 'missing parameters'});
        }

        models.User.findOne({
            attributes: ['email'],
            where: { email: email}
        })
        .then(function(userFound) {
            if (!userFound) {

                bcrypt.hash(password, 5, function( err, bcryptedPassword ) {
                    var newUser = models.User.create({
                        email: email,
                        password: bcryptedPassword,
                        role: role,
                        isAdmin: 0
                    })
                    .then(function(newUser) {
                        return res.status(201).json({
                            'userId': newUser.id
                        })
                    })
                    .catch(function(err) {
                        return res.status(500).json({ 'error': 'cannot add user' });
                    });
                });
            
            } else {
                return res.status(409).json({ 'error': 'user already exist' });
            }
        })
        .catch(function(err) {
            return res.status(500).json({ 'error': 'unable to verify user' });
        });

    },

    login: function(req, res) {

        // Params
        var email = req.body.email;
        var password = req.body.password;

        if (email == null || password == null) { 
            return res.status(400).json({ 'error': 'missing parameters'});
        }

        models.User.findOne({
            where: { email: email}
        })
        .then(function(userFound) {
            if (userFound) {

                bcrypt.compare(password, userFound.password, function(errBycrypt, resBycrypt) {
                    if(resBycrypt) {
                        return res.status(200).json({
                            'userId': userFound.id,
                            'token': jwtUtils.generateTokenForUser(userFound)
                        });
                    } else {
                        return res.status(403).json({ "error": "invalid password" });
                    }
                });
            
            } else {
                return res.status(404).json({ 'error': 'user not exists in DB' });
            }
        })
        .catch(function(err) {
            return res.status(500).json({ 'error': 'unable to verify user' });
        });

    },

    getUserProfile: function(req, res) {
        // Getting auth header
        var headerAuth = req.headers['authorization'];
        var userId = jwtUtils.getUserId(headerAuth);
    
        if (userId < 0)
            return res.status(400).json({ 'error': 'wrong token' });
    
        models.User.findOne({
            attributes: [ 'id', 'lastName', 'firstName', 'email', 'password', 'role' ],
            where: { id: userId }
        }).then(function(user) {
            if (user) {
                res.status(201).json(user);
            } else {
                res.status(404).json({ 'error': 'user not found' });
            }
        }).catch(function(err) {
            res.status(500).json({ 'error': 'cannot fetch user' });
        });
    },

    updateUserProfile: function(req, res) {
        // Getting auth header
        var headerAuth = req.headers['authorization'];
        var userId = jwtUtils.getUserId(headerAuth);

        // Params
        var bio = req.body.bio;

        asyncLib.waterfall([
            function(done) {
                models.User.findOne({
                    attributes: ['id', 'bio'],
                    where: { id: userId }
                }).then(function (userFound) {
                    done(null, userFound);
                })
                .catch(function(err) {
                    return res.status(500).json({ 'error': 'unable to verify user' });
                });
            },
            function(userFound, done) {
                if(userFound) {
                    userFound.update({
                        bio: (bio ? bio : userFound.bio)
                    }).then(function() {
                        done(userFound);
                    }).catch(function(err) {
                        res.status(500).json({ 'error': 'cannot update user' });
                    });
                } else {
                    res.status(404).json({ 'error': 'user not found' });
                }
            },
        ],  function(userFound) {
                if (userFound) {
                    return res.status(201).json(userFound);
                } else {
                    return res.status(500).json({ 'error': 'cannot update user profile' });
                }
            }
        );
    },

    deleteUserProfile: function(req, res, next) {
        const { deleteUser } = req;
        const { SUCCESS, ERROR,  NOT_FOUND } = deleteUser.outputs;

        deleteUser
            .on(SUCCESS, () => {
                res.status(Status.ACCEPTED).end();
            })
            .on(NOT_FOUND, (error) => {
                res.status(Status.NOT_FOUND).json({
                type: 'NotFoundError',
                details: error.details
                });
            })
            .on(ERROR, next);

        deleteUser.execute(Number(req.params.id));
    }
}