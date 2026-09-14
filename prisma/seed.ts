import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config();

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});

const prisma = new PrismaClient({ adapter });

const users = [
  { username: "ali", email: "ali@gmail.com", pin: "12345" },
  { username: "aimal-khan", email: "aimalkhan@gmail.com", pin: "03160" },
  { username: "qasim", email: "qasim@gmail.com", pin: "56134" },
  { username: "mahad", email: "mahad@gmail.com", pin: "78542" },
  { username: "muhammad-fahad", email: "fahad@gmail.com", pin: "46973" },
  { username: "awais", email: "awais@gmail.com", pin: "74381" },
];

async function main() {
  // Clear existing data
  await prisma.retakeRequest.deleteMany();
  await prisma.answer.deleteMany();
  await prisma.attempt.deleteMany();
  await prisma.question.deleteMany();
  await prisma.quiz.deleteMany();
  await prisma.user.deleteMany();

  // Create users
  for (const user of users) {
    const pinHash = await bcrypt.hash(user.pin, 10);
    await prisma.user.create({
      data: {
        username: user.username,
        email: user.email,
        pinHash,
      },
    });
  }
  console.log(`Created ${users.length} users`);

  // Chapter 1: AI Fluency
  const chapter1 = await prisma.quiz.create({
    data: {
      title: "Chapter 1: AI Fluency",
      timeLimit: 600, // 10 minutes
      questions: {
        create: [
          {
            text: "What does LLM stand for in modern Artificial Intelligence?",
            options: [
              "Large Language Model",
              "Low Latency Machine",
              "Linear Logic Matrix",
              "Language Learning Module"
            ],
            correctAnswer: 0,
          },
          {
            text: "Which concept refers to an AI producing convincing but factually incorrect statements?",
            options: ["Overfitting", "Hallucination", "Quantization", "Gradient Descent"],
            correctAnswer: 1,
          },
          {
            text: "What is 'Temperature' used for when configuring LLM responses?",
            options: [
              "Processor hardware temperature limit",
              "Controlling the randomness and creativity of generated text",
              "Determining the training epoch speed",
              "Measuring token throughput"
            ],
            correctAnswer: 1,
          },
          {
            text: "What is RAG (Retrieval-Augmented Generation)?",
            options: [
              "Retraining a model from scratch with new datasets",
              "Combining retrieval of external knowledge with LLM generation",
              "A method to compress deep neural weights",
              "An adversarial attack strategy"
            ],
            correctAnswer: 1,
          },
          {
            text: "What is a 'token' in the context of tokenization for LLMs?",
            options: [
              "An authentication session cookie",
              "A basic chunk of text (word, subword, or character) processed by the model",
              "A cryptographic currency coin",
              "A GPU execution cycle"
            ],
            correctAnswer: 1,
          },
        ],
      },
    },
  });
  console.log(`Created Chapter 1 (ID: ${chapter1.id})`);

  // Chapter 2: Claude 101
  const chapter2 = await prisma.quiz.create({
    data: {
      title: "Chapter 2: Claude 101",
      timeLimit: 600,
      questions: {
        create: [
          {
            text: "Which AI research company developed Claude?",
            options: ["OpenAI", "Anthropic", "DeepMind", "Mistral AI"],
            correctAnswer: 1,
          },
          {
            text: "What safety methodology pioneered by Anthropic guides Claude's training?",
            options: [
              "Constitutional AI",
              "Unsupervised Clustering",
              "Monte Carlo Tree Search",
              "Proof of Authority"
            ],
            correctAnswer: 0,
          },
          {
            text: "Which Claude model tier is known for the highest intelligence and complex reasoning?",
            options: ["Claude Haiku", "Claude Sonnet", "Claude Opus", "Claude Mini"],
            correctAnswer: 2,
          },
          {
            text: "What is Claude's 'Artifacts' feature designed for?",
            options: [
              "Storing historical chat logs in compressed zip files",
              "Displaying dedicated interactive code, documents, SVGs, and web previews side-by-side with chat",
              "Mining cryptocurrency on the browser client",
              "Running automated vulnerability exploits"
            ],
            correctAnswer: 1,
          },
          {
            text: "Which Claude model is optimized for near-instant response speeds and lightweight tasks?",
            options: ["Claude Opus", "Claude Sonnet", "Claude Haiku", "Claude Giant"],
            correctAnswer: 2,
          },
        ],
      },
    },
  });
  console.log(`Created Chapter 2 (ID: ${chapter2.id})`);

  // Chapter 3: AI Prompting 2026
  const chapter3 = await prisma.quiz.create({
    data: {
      title: "Chapter 3: AI Prompting 2026",
      timeLimit: 600,
      questions: {
        create: [
          {
            text: "What is 'Few-Shot Prompting'?",
            options: [
              "Giving the model a few attempts to guess before grading",
              "Providing a few input-output examples inside the prompt before the target query",
              "Limiting the output response to a few words",
              "Using small prompts with less than 5 tokens"
            ],
            correctAnswer: 1,
          },
          {
            text: "Why is 'Chain-of-Thought' (CoT) prompting effective for complex tasks?",
            options: [
              "It forces the model to articulate intermediate reasoning steps before arriving at the conclusion",
              "It connects multiple models into a blockchain",
              "It bypasses all token limit constraints",
              "It minimizes response latency to zero"
            ],
            correctAnswer: 0,
          },
          {
            text: "What role does a 'System Prompt' play in conversational AI architectures?",
            options: [
              "It configures the database connection strings",
              "It establishes persona, instructions, tone, and guardrails for the model",
              "It sends automated notifications to system administrators",
              "It restarts the server during high load"
            ],
            correctAnswer: 1,
          },
          {
            text: "Which XML tags are widely recognized as best practice when organizing Anthropic Claude prompts?",
            options: [
              "<instructions>, <context>, and <examples>",
              "<table>, <tr>, and <td>",
              "<script>, <div>, and <span>",
              "<select>, <from>, and <where>"
            ],
            correctAnswer: 0,
          },
          {
            text: "What is 'Prompt Injection' and how is it mitigated?",
            options: [
              "Injecting SQL directly into the prompt database",
              "Untrusted input manipulating the model to ignore instructions; mitigated by delimiter tags and strict system rules",
              "Adding speed-enhancing GPU instructions to LLM weights",
              "Formatting text in CSS rather than markdown"
            ],
            correctAnswer: 1,
          },
        ],
      },
    },
  });
  console.log(`Created Chapter 3 (ID: ${chapter3.id})`);

  // Mathematics MCQs
  const mathQuiz = await prisma.quiz.create({
    data: {
      title: "Mathematics MCQs",
      timeLimit: 600,
      questions: {
        create: [
          {
            text: "What is 15 + 27?",
            options: ["40", "42", "44", "41"],
            correctAnswer: 1,
          },
          {
            text: "What is 9 × 7?",
            options: ["63", "56", "72", "54"],
            correctAnswer: 0,
          },
          {
            text: "What is 144 ÷ 12?",
            options: ["11", "13", "12", "14"],
            correctAnswer: 2,
          },
          {
            text: "What is 25% of 80?",
            options: ["15", "25", "20", "30"],
            correctAnswer: 2,
          },
          {
            text: "What is the square root of 81?",
            options: ["7", "8", "9", "10"],
            correctAnswer: 2,
          },
        ],
      },
    },
  });
  console.log(`Created Math Quiz (ID: ${mathQuiz.id})`);
  console.log("Seed completed successfully!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
