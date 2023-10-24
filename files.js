import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const files = {
    saveFile: (name, content, dirs = []) => {
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);
        let pathStr = path.join(__dirname, ...dirs, name);
        fs.writeFile(pathStr, content, err => {
            if (err) {
                console.error(err);
            }
        });
    },
    getStats: (filename, dirs = []) => {
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);
        let pathStr = path.join(__dirname, ...dirs, filename);
        let stat = fs.statSync(pathStr);
        return { createdAt: stat.birthtime, modifiedAt: stat.mtime };
    }
};

export default files;