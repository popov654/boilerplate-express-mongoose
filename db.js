import mongoose from 'mongoose';

const Db = {
    connect: () => {
        return mongoose.connect('mongodb://127.0.0.1:27017/cloudfave').then(() => {
            console.log("Connected to MongoDB");
        }).catch((err) => {
            console.log("MongoDB connection error:");
            console.log(err);
        });
    }
};

export default Db;