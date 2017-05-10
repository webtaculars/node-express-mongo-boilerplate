var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var bcrypt = require('bcrypt-nodejs');


var UserSchema = new Schema({

    name: { type: String, required: true },
    email: { type: String, required: true, lowercase: true, index: { unique: true } },
    password: { type: String, select: true },
    mobile: { type: String, required: true },

});


//password hashing
UserSchema.pre('save', function(next) {

    var user = this;

    if (!user.isModified('password')) return next();

    bcrypt.hash(user.password, null, null, function(err, hash) {

        if (err) return (err);

        user.password = hash;
        next();
    });
});


//method to compare password
UserSchema.methods.comparePassword = function(password) {

    var user = this;

    return bcrypt.compareSync(password, user.password);
}



module.exports = mongoose.model('User', UserSchema);
