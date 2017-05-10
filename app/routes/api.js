var User = require('../models/user');
var config = require('../../config');
var secretKey = config.secretKey;
var jsonwebtoken = require('jsonwebtoken');

// CREATE USER TOKEN
function createUserToken(user) {

    var token = jsonwebtoken.sign({

        id: user._id,
        email: user.email,
        mobile: user.mobile,
        name: user.name

    }, secretKey, {
        expiresIn: 900000000
    });

    return token;
}


module.exports = function(app, express, io) {

    var api = express.Router();


    api.post('/signup', function(req, res) {
        var user = new User({
            name: req.body.name,
            email: req.body.email,
            mobile: req.body.mobile,
            password: req.body.password
        })

        user.save(function(err, user) {
            if (err) {
                return console.log(err);
            } else {
                var token = createUserToken(user);
                res.json({
                    success: true,
                    token: token
                })
            }
        })

    })


    api.post('/login', function(req, res) {
        User.findOne({
            email: req.body.email
        }).select('name email mobile password').exec(function(err, user) {

            if (err) throw err;

            else if (!user) {

                res.send({ message: "User doesn't exist" });
            } else if (user) {

                var validPassword = user.comparePassword(req.body.password);

                if (!validPassword) {
                    res.send({ message: "Invalid Password" });
                } else {

                    var token = createUserToken(user);

                    res.json({
                        success: true,
                        message: "Successfully login",
                        token: token
                    });

                }

            }
        });

    })


    // Middleware
    api.use(function(req, res, next) {
        var token = req.body.token || req.param('token') || req.headers['x-access-token'];

        if (token) {
            jsonwebtoken.verify(token, secretKey, function(err, decoded) {
                if (err) {
                    res.status(403).send({ success: false, message: "Failed to connect" });
                } else {
                    req.decoded = decoded;
                    next();
                }
            });
        } else {

            res.status(403).send({ success: false, message: "false token" });
        }

    });

    api.get('/me', function(req, res) {
        res.json(req.decoded)
    })


    return api;
}
