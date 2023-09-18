import mongoose, { SchemaTypes } from "mongoose";

const { Schema, model } = mongoose;

const sessionSchema = new Schema({
    userId: {
        type: SchemaTypes.ObjectId,
        ref: 'User'
    },
    ip: {
        type: String
    },
    startedAt: {
        type: Date,
        default: () => Date.now(),
        immutable: true
    },
    lastAccess: {
        type: Date,
        default: () => Date.now()
    }
});

const Session = model("Session", sessionSchema);
export default Session;