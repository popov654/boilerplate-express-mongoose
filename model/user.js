import mongoose, { SchemaTypes } from "mongoose";

const { Schema, model } = mongoose;

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        minLength: 10,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    registeredAt: {
        type: Date,
        default: () => Date.now(),
        immutable: true
    }
});

const User = model("User", userSchema);
export default User;