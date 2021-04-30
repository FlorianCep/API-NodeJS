// Imports
const express = require('express');
const usersCtrl = require('./routes/usersCtrl');

// Routes
exports.router = (function() {
    const apiRouter = express.Router();

    // Users routes
    apiRouter.route('/users/register/').post(usersCtrl.register);
    apiRouter.route('/users/login/').post(usersCtrl.login);
    apiRouter.route('/users/me/').get(usersCtrl.getUserProfile);
    apiRouter.route('/users/me/').put(usersCtrl.updateUserProfile);
    apiRouter.route('/users/me/').delete(usersCtrl.deleteUserProfile);

    return apiRouter;
})();