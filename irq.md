**NOTE**: These changes will be made to the [extended_apis](https://github.com/Bareflank/extended_apis) and not the main Bareflank repo as we want to keep Bareflank simple. This RFC proposes modifications of the existing event API, with a focus on external interrupts.

## Reasoning for Modifications of RFC #424
There are a few reasons for this new event RFC:
1. The event API in RFC #424 (summarized below) uses 'event' to refer to external interrupts, however several other types of events may be injected into a guest, including NMIs, software interrupts, and exceptions. The different types can be broadly classified as interrupts or exceptions.  Events in these classes need different arguments e.g. exceptions may have error codes but (hardware) interrupts do not, and the complexity of virtualization varies significantly between interrupts and exceptions.  As such, I believe that separate RFCs (or separate sections in this RFC) are warranted so that the intent of the API is clear.
2. The description of the API states that event injection will be performed using the following calls:
    - `enable_event_management`:  This configures interrupts to trap to VMX-root and effectively gives the VMM ownership of interrupts.
    - `inject_event`: This queues the event and enables interrupt window exiting.
But this is one particular way to inject an event into a guest, and requires the VMM to take ownership of all platform interrupts.





### Summary of Event API from RFC #424
#### Public functions
- `vmcs::enable_event_management`
- `vmcs::disable_event_management`
- `exit_handler::inject_event(vector_type vector, event_type type, error_code_type ec)`
- `exit_handler::handle_exit__event(vector_type vector, event_type type, error_code_type ec, bool blocking)`
- `exit_handler::log_event(vector_type vector, event_type type, error_code_type ec, bool blocking)`
- `exit_handler::log_events(bool enable)`
- `exit_handler::clear_event_log()`
- `exit_handler::event_log()`

#### VMcalls:
- Register vmcalls:
  - r2 = eapis_cat__event_management (0x6000)
       * r3 = eapis_fun__enable_event_management (0x1)
        * r3 = eapis_fun__disable_event_management (0x2)

- JSON vmcalls:
  * {"command": "enable_event_management", "enabled": true/false}
  * {"command": "log_events", "enabled": true/false}
  * {"command": "clear_event_log"}
  * {"command": "event_log"} -> log (std::map -> JSON)

#### Default state:
By default, event management will be disabled.

The rest of this issue will propose changes to the API above that specifies the services and scope of **interrupt** injection.

## Interrupt









