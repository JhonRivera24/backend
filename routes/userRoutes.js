// routes/userRoutes.js
import express from 'express';
import userController from '../controllers/userController.js';

const router = express.Router();

router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/get-security-question', userController.getSecurityQuestion);
router.post('/reset-password', userController.resetPassword);
router.post("/refresh", userController.refreshToken);
router.post('/validate-answer', controller.validateSecurityAnswer);

export default router;
