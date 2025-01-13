const nodemailer = require('nodemailer');
const Queue = require('bull');

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT,
            secure: true,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        // Initialize queue with retry strategy
        this.emailQueue = new Queue('email-queue', {
            redis: {
                host: process.env.REDIS_HOST || 'localhost',
                port: process.env.REDIS_PORT || 6379,
                retryStrategy: (times) => {
                    const delay = Math.min(times * 50, 2000);
                    return delay;
                }
            },
            defaultJobOptions: {
                attempts: 3,
                backoff: {
                    type: 'exponential',
                    delay: 1000
                }
            }
        });

        // Process queue
        this.emailQueue.process(async (job) => {
            return this.sendEmail(job.data);
        });

        // Handle failed jobs
        this.emailQueue.on('failed', (job, err) => {
            console.error('Email job failed:', err);
            // Implement fallback method here if needed
            this.handleFailedEmail(job.data);
        });
    }

    async sendEmail({ to, subject, html }) {
        try {
            await this.transporter.sendMail({
                from: process.env.SMTP_FROM,
                to,
                subject,
                html
            });
        } catch (error) {
            console.error('Email send error:', error);
            throw error;
        }
    }

    // Fallback method for failed emails
    async handleFailedEmail(emailData) {
        try {
            // Implement a fallback method
            // For example, save to database for retry later
            console.log('Implementing fallback for failed email:', emailData);
        } catch (error) {
            console.error('Fallback handling failed:', error);
        }
    }

    async sendPasswordHint(email, hint) {
        const emailContent = {
            to: email,
            subject: 'Password Manager - Your Master Password Hint',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Forgotten master password</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #ffffff;
                        }
                        .header {
                            background-color: #8d9199;
                            color: white;
                            padding: 20px;
                            text-align: center;
                            border-radius: 5px 5px 0 0;
                        }
                        .content {
                            padding: 20px;
                            background-color: #f9fafb;
                            border: 1px solid #e5e7eb;
                            border-radius: 0 0 5px 5px;
                        }
                        .info-box {
                            background-color: #ffffff;
                            border: 1px solid #e5e7eb;
                            border-radius: 5px;
                            padding: 15px;
                            margin: 15px 0;
                        }
                        .important-note {
                            background-color: #fef2f2;
                            border: 1px solid #fee2e2;
                            border-radius: 5px;
                            padding: 15px;
                            margin: 15px 0;
                            color: #991b1b;
                        }
                        .footer {
                            text-align: center;
                            margin-top: 20px;
                            padding: 20px;
                            color: #6b7280;
                            font-size: 0.875rem;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2 style="margin:0;">Password Manager</h2>
                        </div>
                        
                        <div class="content">
                            <p>Hello,</p>
                            <br>
                            
                            <p>You recently requested your master password hint. Here's the information to help you remember your master password.</p>

                            <div class="info-box">
                                <p style="margin:0;"><strong>Your master password hint:</strong><br>
                                ${hint || 'No hint set'}</p>
                            </div>

                            <br>
                            <p><em>Note: Your 'master password hint' is not your master password. 
                            It's a phrase you set up to help remind you of your actual master password.</em></p>
                            <br>

                            <div class="important-note">
                                <strong>Important Security Notice:</strong>
                                <p style="margin:10px 0 0 0;">Nobody at Password Manager ever knows your master password. 
                                We can't reset it for you. Use your hint or the account recovery process to get back into your account.</p>
                            </div>
                            <br>

                            <p>If you still can't remember your master password, you can request a password reset through our account recovery process.</p>
                        </div>

                        <div class="footer">
                            <p>This is an automated message, please do not reply to this email.</p>
                            <p>&copy; ${new Date().getFullYear()} Password Manager. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        try {
            await this.emailQueue.add(emailContent);
        } catch (error) {
            console.error('Queue error, trying direct send:', error);
            await this.sendEmail(emailContent);
        }
    }

    async sendPasswordRecovery(email, recoveryCode) {
        const emailContent = {
            to: email,
            subject: 'Password Manager - Your Recovery Code',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Your Recovery Code</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #ffffff;
                        }
                        .header {
                            background-color: #8d9199;
                            color: white;
                            padding: 20px;
                            text-align: center;
                            border-radius: 5px 5px 0 0;
                        }
                        .content {
                            padding: 20px;
                            background-color: #f9fafb;
                            border: 1px solid #e5e7eb;
                            border-radius: 0 0 5px 5px;
                        }
                        .important-note {
                            background-color: #fef2f2;
                            border: 1px solid #fee2e2;
                            border-radius: 5px;
                            padding: 15px;
                            margin: 15px 0;
                            color: #991b1b;
                        }
                        .recovery-code {
                            background-color: #f3f4f6;
                            padding: 15px;
                            border-radius: 5px;
                            font-family: monospace;
                            font-size: 2em;
                            text-align: center;
                            letter-spacing: 2px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>Password Manager Recovery</h2>
                        </div>
                        
                        <div class="content">
                            <p>Hello,</p>
                            <br>
                            <p>You've requested to recover your Password Manager account. 
                            Use the recovery code below to reset your master password:</p>
                            <br>

                            <div class="recovery-code">
                                ${recoveryCode}
                            </div>
                            <br>

                            <p><strong>This code will expire in 1 hour.</strong></p>
                            <br>

                            <div class="important-note">
                                <strong>Important Security Notice:</strong>
                                <ul>
                                    <li>Never share this code with anyone</li>
                                    <li>Our staff will never ask for this code</li>
                                    <li>Only enter this code on the official Password Manager website</li>
                                </ul>
                            </div>
                            <br>

                            <p>If you didn't request this recovery, please ignore this email 
                            and consider updating your account security settings.</p>
                        </div>
                        <br>

                        <div class="footer">
                            <p>This is an automated message, please do not reply.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        try {
            await this.emailQueue.add(emailContent);
        } catch (error) {
            console.error('Queue error, trying direct send:', error);
            await this.sendEmail(emailContent);
        }
    }

    async sendShareNotification(recipientEmail, sharedByEmail, sharedPasswordName) {
        const emailContent = {
            to: recipientEmail,
            subject: `Password shared with you by ${sharedByEmail}`,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Password Manager - Shared Password</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                            margin: 0;
                            padding: 0;
                        }
                        .container {
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #ffffff;
                        }
                        .header {
                            background-color: #8d9199;
                            color: white;
                            padding: 20px;
                            text-align: center;
                            border-radius: 5px 5px 0 0;
                        }
                        .content {
                            padding: 20px;
                            background-color: #f9fafb;
                            border: 1px solid #e5e7eb;
                            border-radius: 0 0 5px 5px;
                        }
                        
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h2>LockdownPass - Password Manager</h2>
                        </div>
                        
                        <div class="content">
                            <p>Hello,</p>
                            <br>
                            <p>A password has been shared with you:</p>
                            <ul>
                                <li><strong>Title:</strong> ${sharedPasswordName}</li>
                                <li><strong>Shared By:</strong> ${sharedByEmail}</li>
                            </ul>
                            <p>You can access this password by logging into your Password Manager account.</p>
                            <br>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        try {
            await this.emailQueue.add(emailContent);
        } catch (error) {
            console.error('Queue error, trying direct send:', error);
            await this.sendEmail(emailContent);
        }
    }
}

// Create singleton instance
const emailService = new EmailService();
module.exports = emailService;

