var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var jsonwebtoken = require('jsonwebtoken');
var config = require('./config');
var User = require('./app/models/user');

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

var port = process.env.PORT || 8080;

mongoose.connect(config.database);
app.set('superSecret', config.secret);

var router = express.Router();



router.post('/authenticate', function(req, res) {

    User.findOne({
        name: req.body.name
    }, function(err, user) {

        if (err) throw err;

        if (!user) {
            res.jsonp({ success: false, message: 'Authentication failed. User not found.' });
        } else if (user) {

            if (user.password != req.body.password) {
                res.jsonp({ success: false, message: 'Authentication failed. Wrong password.' });
            } else {

                var token = jsonwebtoken.sign(user, app.get('superSecret'), {
                    expiresIn: 86400
                });

                res.jsonp({
                    success: true,
                    message: 'Enjoy your token!',
                    token: token
                });
            }
        }
    });
});


router.use(function(req, res, next) {

    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    if (token) {

        jsonwebtoken.verify(token, app.get('superSecret'), function(err, decoded) {
            if (err) {
                return res.json({ success: false, message: 'Failed to authenticate token.' });
            } else {
                req.decoded = decoded;
                next();
            }
        });

    } else {
        return res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
    }
});


router.route('/users/:user_id')

    .get(function(req, res) {
        User.findById(req.params.user_id, function(err, user) {
            if (err)
                res.send(err);
            res.jsonp(user);
        });
    })

    .put(function(req, res) {

        User.findById(req.params.user_id, function(err, user) {

            if (err)
                res.send(err);

            user.name = req.body.name;
            user.password = req.body.password;
            user.admin = req.body.admin;

            user.save(function(err) {
                if (err)
                    res.send(err);

                res.jsonp({ message: 'User updated!' });
            });

        });
    })

    .delete(function(req, res) {
        User.remove({
            _id: req.params.user_id
        }, function(err, user) {
            if (err)
                res.send(err);

            res.jsonp({ message: 'Successfully deleted' });
        });
    });

router.route('/users')

    .post(function(req, res) {

        var user = new User();
        user.name = req.body.name;
        user.password = req.body.password;
        user.admin = req.body.admin;

        user.save(function(err) {
            if (err)
                res.send(err);

            res.jsonp({ message: 'User created!' });
        });

    })

    .get(function(req, res) {
        User.find({}, function(err, users) {
            res.jsonp(users);
        });
    });

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    next();
});

app.use('/api', router);

app.listen(port);

console.log('magic happens on port ' + port);