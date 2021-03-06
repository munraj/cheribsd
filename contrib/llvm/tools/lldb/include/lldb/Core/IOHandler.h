//===-- IOHandler.h ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_IOHandler_h_
#define liblldb_IOHandler_h_

#include <string.h>

#include <stack>

#include "lldb/lldb-public.h"
#include "lldb/lldb-enumerations.h"
#include "lldb/Core/ConstString.h"
#include "lldb/Core/Error.h"
#include "lldb/Core/Flags.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StringList.h"
#include "lldb/Core/ValueObjectList.h"
#include "lldb/Host/Mutex.h"
#include "lldb/Host/Predicate.h"

namespace curses
{
    class Application;
    typedef std::unique_ptr<Application> ApplicationAP;
}

namespace lldb_private {

    class IOHandler
    {
    public:
        enum class Type {
            CommandInterpreter,
            CommandList,
            Confirm,
            Curses,
            Expression,
            ProcessIO,
            PythonInterpreter,
            PythonCode,
            Other
        };

        IOHandler (Debugger &debugger,
                   IOHandler::Type type);

        IOHandler (Debugger &debugger,
                   IOHandler::Type type,
                   const lldb::StreamFileSP &input_sp,
                   const lldb::StreamFileSP &output_sp,
                   const lldb::StreamFileSP &error_sp,
                   uint32_t flags);

        virtual
        ~IOHandler ();

        // Each IOHandler gets to run until it is done. It should read data
        // from the "in" and place output into "out" and "err and return
        // when done.
        virtual void
        Run () = 0;

        // Hide any characters that have been displayed so far so async
        // output can be displayed. Refresh() will be called after the
        // output has been displayed.
        virtual void
        Hide () = 0;
        
        // Called when the async output has been received in order to update
        // the input reader (refresh the prompt and redisplay any current
        // line(s) that are being edited
        virtual void
        Refresh () = 0;

        // Called when an input reader should relinquish its control so another
        // can be pushed onto the IO handler stack, or so the current IO
        // handler can pop itself off the stack

        virtual void
        Cancel () = 0;

        // Called when CTRL+C is pressed which usually causes
        // Debugger::DispatchInputInterrupt to be called.
        
        virtual bool
        Interrupt () = 0;
        
        virtual void
        GotEOF() = 0;
        
        virtual bool
        IsActive ()
        {
            return m_active && !m_done;
        }

        virtual void
        SetIsDone (bool b)
        {
            m_done = b;
        }

        virtual bool
        GetIsDone ()
        {
            return m_done;
        }

        Type
        GetType () const
        {
            return m_type;
        }

        virtual void
        Activate ()
        {
            m_active = true;
        }
        
        virtual void
        Deactivate ()
        {
            m_active = false;
        }

        virtual const char *
        GetPrompt ()
        {
            // Prompt support isn't mandatory
            return NULL;
        }
        
        virtual bool
        SetPrompt (const char *prompt)
        {
            // Prompt support isn't mandatory
            return false;
        }
        
        virtual ConstString
        GetControlSequence (char ch)
        {
            return ConstString();
        }

        virtual const char *
        GetCommandPrefix ()
        {
            return NULL;
        }
        
        virtual const char *
        GetHelpPrologue()
        {
            return NULL;
        }

        int
        GetInputFD();
        
        int
        GetOutputFD();
        
        int
        GetErrorFD();

        FILE *
        GetInputFILE();
        
        FILE *
        GetOutputFILE();
        
        FILE *
        GetErrorFILE();

        lldb::StreamFileSP &
        GetInputStreamFile();
        
        lldb::StreamFileSP &
        GetOutputStreamFile();
        
        lldb::StreamFileSP &
        GetErrorStreamFile();

        Debugger &
        GetDebugger()
        {
            return m_debugger;
        }

        void *
        GetUserData ()
        {
            return m_user_data;
        }

        void
        SetUserData (void *user_data)
        {
            m_user_data = user_data;
        }

        Flags &
        GetFlags ()
        {
            return m_flags;
        }

        const Flags &
        GetFlags () const
        {
            return m_flags;
        }

        //------------------------------------------------------------------
        /// Check if the input is being supplied interactively by a user
        ///
        /// This will return true if the input stream is a terminal (tty or
        /// pty) and can cause IO handlers to do different things (like
        /// for a confirmation when deleting all breakpoints).
        //------------------------------------------------------------------
        bool
        GetIsInteractive ();

        //------------------------------------------------------------------
        /// Check if the input is coming from a real terminal.
        ///
        /// A real terminal has a valid size with a certain number of rows
        /// and columns. If this function returns true, then terminal escape
        /// sequences are expected to work (cursor movement escape sequences,
        /// clearing lines, etc).
        //------------------------------------------------------------------
        bool
        GetIsRealTerminal ();
        
        void
        SetPopped (bool b);
        
        void
        WaitForPop ();
        
    protected:
        Debugger &m_debugger;
        lldb::StreamFileSP m_input_sp;
        lldb::StreamFileSP m_output_sp;
        lldb::StreamFileSP m_error_sp;
        Predicate<bool> m_popped;
        Flags m_flags;
        Type m_type;
        void *m_user_data;
        bool m_done;
        bool m_active;

    private:
        DISALLOW_COPY_AND_ASSIGN (IOHandler);
    };

    
    //------------------------------------------------------------------
    /// A delegate class for use with IOHandler subclasses.
    ///
    /// The IOHandler delegate is designed to be mixed into classes so
    /// they can use an IOHandler subclass to fetch input and notify the
    /// object that inherits from this delegate class when a token is
    /// received.
    //------------------------------------------------------------------
    class IOHandlerDelegate
    {
    public:
        enum class Completion {
            None,
            LLDBCommand,
            Expression
        };
        
        IOHandlerDelegate (Completion completion = Completion::None) :
            m_completion(completion),
            m_io_handler_done (false)
        {
        }
        
        virtual
        ~IOHandlerDelegate()
        {
        }
        
        virtual void
        IOHandlerActivated (IOHandler &io_handler)
        {
        }

        virtual void
        IOHandlerDeactivated (IOHandler &io_handler)
        {
        }

        virtual int
        IOHandlerComplete (IOHandler &io_handler,
                           const char *current_line,
                           const char *cursor,
                           const char *last_char,
                           int skip_first_n_matches,
                           int max_matches,
                           StringList &matches);
        
        virtual const char *
        IOHandlerGetFixIndentationCharacters ()
        {
            return NULL;
        }
        
        //------------------------------------------------------------------
        /// Called when a new line is created or one of an identifed set of
        /// indentation characters is typed.
        ///
        /// This function determines how much indentation should be added
        /// or removed to match the recommended amount for the final line.
        ///
        /// @param[in] io_handler
        ///     The IOHandler that responsible for input.
        ///
        /// @param[in] lines
        ///     The current input up to the line to be corrected.  Lines
        ///     following the line containing the cursor are not included.
        ///
        /// @param[in] cursor_position
        ///     The number of characters preceeding the cursor on the final
        ///     line at the time.
        ///
        /// @return
        ///     Returns an integer describing the number of spaces needed
        ///     to correct the indentation level.  Positive values indicate
        ///     that spaces should be added, while negative values represent
        ///     spaces that should be removed.
        //------------------------------------------------------------------
        virtual int
        IOHandlerFixIndentation (IOHandler &io_handler,
                                 const StringList &lines,
                                 int cursor_position)
        {
            return 0;
        }
                        
        //------------------------------------------------------------------
        /// Called when a line or lines have been retrieved.
        ///
        /// This function can handle the current line and possibly call
        /// IOHandler::SetIsDone(true) when the IO handler is done like when
        /// "quit" is entered as a command, of when an empty line is
        /// received. It is up to the delegate to determine when a line
        /// should cause a IOHandler to exit.
        //------------------------------------------------------------------
        virtual void
        IOHandlerInputComplete (IOHandler &io_handler, std::string &data) = 0;

        virtual void
        IOHandlerInputInterrupted (IOHandler &io_handler, std::string &data)
        {
        }

        //------------------------------------------------------------------
        /// Called to determine whether typing enter after the last line in
        /// \a lines should end input.  This function will not be called on
        /// IOHandler objects that are getting single lines.
        /// @param[in] io_handler
        ///     The IOHandler that responsible for updating the lines.
        ///
        /// @param[in] lines
        ///     The current multi-line content.  May be altered to provide
        ///     alternative input when complete.
        ///
        /// @return
        ///     Return an boolean to indicate whether input is complete,
        ///     true indicates that no additional input is necessary, while
        ///     false indicates that more input is required.
        //------------------------------------------------------------------
        virtual bool
        IOHandlerIsInputComplete (IOHandler &io_handler,
                                  StringList &lines)
        {
            // Impose no requirements for input to be considered
            // complete.  subclasses should do something more intelligent.
            return true;
        }
        
        virtual ConstString
        IOHandlerGetControlSequence (char ch)
        {
            return ConstString();
        }
        
        virtual const char *
        IOHandlerGetCommandPrefix ()
        {
            return NULL;
        }

        virtual const char *
        IOHandlerGetHelpPrologue ()
        {
            return NULL;
        }

        //------------------------------------------------------------------
        // Intercept the IOHandler::Interrupt() calls and do something.
        //
        // Return true if the interrupt was handled, false if the IOHandler
        // should continue to try handle the interrupt itself.
        //------------------------------------------------------------------
        virtual bool
        IOHandlerInterrupt (IOHandler &io_handler)
        {
            return false;
        }
    protected:
        Completion m_completion; // Support for common builtin completions
        bool m_io_handler_done;
    };

    //----------------------------------------------------------------------
    // IOHandlerDelegateMultiline
    //
    // A IOHandlerDelegate that handles terminating multi-line input when
    // the last line is equal to "end_line" which is specified in the
    // constructor.
    //----------------------------------------------------------------------
    class IOHandlerDelegateMultiline :
        public IOHandlerDelegate
    {
    public:
        IOHandlerDelegateMultiline (const char *end_line,
                                    Completion completion = Completion::None) :
            IOHandlerDelegate (completion),
            m_end_line((end_line && end_line[0]) ? end_line : "")
        {
        }
        
        virtual
        ~IOHandlerDelegateMultiline ()
        {
        }
        
        virtual ConstString
        IOHandlerGetControlSequence (char ch)
        {
            if (ch == 'd')
                return ConstString (m_end_line + "\n");
            return ConstString();
        }

        virtual bool
        IOHandlerIsInputComplete (IOHandler &io_handler,
                                  StringList &lines)
        {
            // Determine whether the end of input signal has been entered
            const size_t num_lines = lines.GetSize();
            if (num_lines > 0 && lines[num_lines - 1] == m_end_line)
            {
                // Remove the terminal line from "lines" so it doesn't appear in
                // the resulting input and return true to indicate we are done
                // getting lines
                lines.PopBack();
                return true;
            }
            return false;
        }
    protected:
        const std::string m_end_line;
    };
    
    
    class IOHandlerEditline : public IOHandler
    {
    public:
        IOHandlerEditline (Debugger &debugger,
                           IOHandler::Type type,
                           const char *editline_name, // Used for saving history files
                           const char *prompt,
                           const char *continuation_prompt,
                           bool multi_line,
                           bool color_prompts,
                           uint32_t line_number_start, // If non-zero show line numbers starting at 'line_number_start'
                           IOHandlerDelegate &delegate);

        IOHandlerEditline (Debugger &debugger,
                           IOHandler::Type type,
                           const lldb::StreamFileSP &input_sp,
                           const lldb::StreamFileSP &output_sp,
                           const lldb::StreamFileSP &error_sp,
                           uint32_t flags,
                           const char *editline_name, // Used for saving history files
                           const char *prompt,
                           const char *continuation_prompt,
                           bool multi_line,
                           bool color_prompts,
                           uint32_t line_number_start, // If non-zero show line numbers starting at 'line_number_start'
                           IOHandlerDelegate &delegate);
        
        virtual
        ~IOHandlerEditline ();
        
        virtual void
        Run ();
        
        virtual void
        Hide ();

        virtual void
        Refresh ();

        virtual void
        Cancel ();

        virtual bool
        Interrupt ();
        
        virtual void
        GotEOF();
        
        virtual void
        Activate ();

        virtual void
        Deactivate ();

        virtual ConstString
        GetControlSequence (char ch)
        {
            return m_delegate.IOHandlerGetControlSequence (ch);
        }

        virtual const char *
        GetCommandPrefix ()
        {
            return m_delegate.IOHandlerGetCommandPrefix ();
        }

        virtual const char *
        GetHelpPrologue ()
        {
            return m_delegate.IOHandlerGetHelpPrologue ();
        }

        virtual const char *
        GetPrompt ();
        
        virtual bool
        SetPrompt (const char *prompt);
        
        const char *
        GetContinuationPrompt ();
        
        void
        SetContinuationPrompt (const char *prompt);
        
        bool
        GetLine (std::string &line, bool &interrupted);
        
        bool
        GetLines (StringList &lines, bool &interrupted);
        
        void
        SetBaseLineNumber (uint32_t line);
        
        bool
        GetInterruptExits ()
        {
            return m_interrupt_exits;
        }

        void
        SetInterruptExits (bool b)
        {
            m_interrupt_exits = b;
        }
        
        const StringList *
        GetCurrentLines () const
        {
            return m_current_lines_ptr;
        }
        
        uint32_t
        GetCurrentLineIndex () const;

    private:
#ifndef LLDB_DISABLE_LIBEDIT
        static bool
        IsInputCompleteCallback (Editline *editline,
                                 StringList &lines,
                                 void *baton);
        
        static int
        FixIndentationCallback (Editline *editline,
                                const StringList &lines,
                                int cursor_position,
                                void *baton);
        
        static int AutoCompleteCallback (const char *current_line,
                                         const char *cursor,
                                         const char *last_char,
                                         int skip_first_n_matches,
                                         int max_matches,
                                         StringList &matches,
                                         void *baton);
#endif

    protected:
#ifndef LLDB_DISABLE_LIBEDIT
        std::unique_ptr<Editline> m_editline_ap;
#endif
        IOHandlerDelegate &m_delegate;
        std::string m_prompt;
        std::string m_continuation_prompt;
        StringList *m_current_lines_ptr;
        uint32_t m_base_line_number; // If non-zero, then show line numbers in prompt
        uint32_t m_curr_line_idx;
        bool m_multi_line;
        bool m_color_prompts;
        bool m_interrupt_exits;
    };
    
    // The order of base classes is important. Look at the constructor of IOHandlerConfirm
    // to see how.
    class IOHandlerConfirm :
        public IOHandlerDelegate,
        public IOHandlerEditline
    {
    public:
        IOHandlerConfirm (Debugger &debugger,
                          const char *prompt,
                          bool default_response);
        
        virtual
        ~IOHandlerConfirm ();
                
        bool
        GetResponse () const
        {
            return m_user_response;
        }
        
        virtual int
        IOHandlerComplete (IOHandler &io_handler,
                           const char *current_line,
                           const char *cursor,
                           const char *last_char,
                           int skip_first_n_matches,
                           int max_matches,
                           StringList &matches);
        
        virtual void
        IOHandlerInputComplete (IOHandler &io_handler, std::string &data);

    protected:
        const bool m_default_response;
        bool m_user_response;
    };

    class IOHandlerCursesGUI :
        public IOHandler
    {
    public:
        IOHandlerCursesGUI (Debugger &debugger);
        
        virtual
        ~IOHandlerCursesGUI ();
        
        virtual void
        Run ();
        
        virtual void
        Hide ();
        
        virtual void
        Refresh ();

        virtual void
        Cancel ();

        virtual bool
        Interrupt ();
        
        virtual void
        GotEOF();
        
        virtual void
        Activate ();
        
        virtual void
        Deactivate ();

    protected:
        curses::ApplicationAP m_app_ap;
    };

    class IOHandlerCursesValueObjectList :
        public IOHandler
    {
    public:
        IOHandlerCursesValueObjectList (Debugger &debugger, ValueObjectList &valobj_list);
        
        virtual
        ~IOHandlerCursesValueObjectList ();
        
        virtual void
        Run ();
        
        virtual void
        Hide ();
        
        virtual void
        Refresh ();
        
        virtual bool
        HandleInterrupt ();
        
        virtual void
        GotEOF();
    protected:
        ValueObjectList m_valobj_list;
    };

    class IOHandlerStack
    {
    public:
        
        IOHandlerStack () :
            m_stack(),
            m_mutex(Mutex::eMutexTypeRecursive),
            m_top (NULL)
        {
        }
        
        ~IOHandlerStack ()
        {
        }
        
        size_t
        GetSize () const
        {
            Mutex::Locker locker (m_mutex);
            return m_stack.size();
        }
        
        void
        Push (const lldb::IOHandlerSP& sp)
        {
            if (sp)
            {
                Mutex::Locker locker (m_mutex);
                sp->SetPopped (false);
                m_stack.push_back (sp);
                // Set m_top the non-locking IsTop() call
                m_top = sp.get();
            }
        }
        
        bool
        IsEmpty () const
        {
            Mutex::Locker locker (m_mutex);
            return m_stack.empty();
        }
        
        lldb::IOHandlerSP
        Top ()
        {
            lldb::IOHandlerSP sp;
            {
                Mutex::Locker locker (m_mutex);
                if (!m_stack.empty())
                    sp = m_stack.back();
            }
            return sp;
        }
        
        void
        Pop ()
        {
            Mutex::Locker locker (m_mutex);
            if (!m_stack.empty())
            {
                lldb::IOHandlerSP sp (m_stack.back());
                m_stack.pop_back();
                sp->SetPopped (true);
            }
            // Set m_top the non-locking IsTop() call
            if (m_stack.empty())
                m_top = NULL;
            else
                m_top = m_stack.back().get();
        }

        Mutex &
        GetMutex()
        {
            return m_mutex;
        }
      
        bool
        IsTop (const lldb::IOHandlerSP &io_handler_sp) const
        {
            return m_top == io_handler_sp.get();
        }

        bool
        CheckTopIOHandlerTypes (IOHandler::Type top_type, IOHandler::Type second_top_type)
        {
            Mutex::Locker locker (m_mutex);
            const size_t num_io_handlers = m_stack.size();
            if (num_io_handlers >= 2 &&
                m_stack[num_io_handlers-1]->GetType() == top_type &&
                m_stack[num_io_handlers-2]->GetType() == second_top_type)
            {
                return true;
            }
            return false;
        }
        ConstString
        GetTopIOHandlerControlSequence (char ch)
        {
            if (m_top)
                return m_top->GetControlSequence(ch);
            return ConstString();
        }

        const char *
        GetTopIOHandlerCommandPrefix()
        {
            if (m_top)
                return m_top->GetCommandPrefix();
            return NULL;
        }
        
        const char *
        GetTopIOHandlerHelpPrologue()
        {
            if (m_top)
                return m_top->GetHelpPrologue();
            return NULL;
        }

    protected:        
        
        typedef std::vector<lldb::IOHandlerSP> collection;
        collection m_stack;
        mutable Mutex m_mutex;
        IOHandler *m_top;
        
    private:
        
        DISALLOW_COPY_AND_ASSIGN (IOHandlerStack);
    };

} // namespace lldb_private

#endif // #ifndef liblldb_IOHandler_h_
