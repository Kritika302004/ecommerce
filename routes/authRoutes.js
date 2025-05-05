import express from 'express';
import { registerController} from '../controller/authController.js'
import { loginController } from '../controller/authController.js';
import { testController } from '../controller/authController.js';
import { isAdmin, requireSignIn } from '../middlewares/authMiddleware.js';
//router object
const router = express.Router();

//routing
//Register || Method Post
router.post('/register', registerController);

//LOGIN || Post
router.post('/login', loginController);

//test routes
router.get('/test', requireSignIn, isAdmin, testController);

//protected route auth
router.get("/user-auth", requireSignIn, (req , res) => {
    res.status(200).send({ok: true});

});

export default router;
